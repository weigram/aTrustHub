package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/dial"
	zjuLog "github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/underlay"

	"github.com/qy/easyconnect/internal/model"
)

// ZJUOptions configure the ZJU-Connect backed connector.
type ZJUOptions struct {
	// DataDir keeps the aTrust client data (device ID and cookies) of each
	// access point.
	DataDir string
	// SecondaryDNS resolves names the VPN DNS cannot, default
	// 114.114.114.114.
	SecondaryDNS string
	// DNSTTL is the resolver cache TTL in seconds.
	DNSTTL uint64
	// Debug turns on ZJU-Connect's debug log.
	Debug bool
}

// NewZJUConnector returns a Connector that logs in with ZJU-Connect's
// aTrust client. One call runs one complete login: its own underlay dialer,
// client, gVisor netstack, resolver and SOCKS dialer.
func NewZJUConnector(opts ZJUOptions) Connector {
	if opts.DNSTTL == 0 {
		opts.DNSTTL = 600
	}
	if opts.SecondaryDNS == "" {
		opts.SecondaryDNS = "114.114.114.114"
	}
	return func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
		return connectZJU(ctx, opts, point, creds)
	}
}

func connectZJU(ctx context.Context, opts ZJUOptions, point model.AccessPoint, creds Credentials) (Session, error) {
	if opts.Debug {
		zjuLog.EnableDebug()
	}

	// Resolve the VPN server's own hostname with a public DNS, so a running
	// global TUN (which rewrites system DNS to the tunnel) does not break
	// logging in to another access point.
	under, err := underlay.New(underlay.Options{
		AutoDetect:     true,
		LocalDNSServer: opts.SecondaryDNS,
	})
	if err != nil {
		return nil, fmt.Errorf("创建底层拨号器：%w", err)
	}
	cleanupUnderlay := true
	defer func() {
		if cleanupUnderlay {
			_ = under.Close()
		}
	}()

	clientData, err := readClientData(opts.DataDir, point.ID)
	if err != nil {
		return nil, err
	}

	loginMethod, err := zjuLoginMethod(ctx, point, creds)
	if err != nil {
		return nil, err
	}

	// Resume the saved session when possible: Setup then skips the login
	// entirely, so a WeCom point does not ask for a new QR code after a
	// disconnect. Everything it needs is already on disk.
	resumeSID, resumeDevice := savedSessionIDs(clientData)
	resourceData, _ := readResourceDump(opts.DataDir, point.ID)

	client := atrustclient.NewClient(atrustclient.ClientOptions{
		Session: atrustclient.SessionOptions{
			Username: point.Username,
			SID:      resumeSID,
			DeviceID: resumeDevice,
		},
		UnderlayDialer: under,
	})
	cleanupClient := true
	defer func() {
		if cleanupClient {
			client.Close()
		}
	}()

	// ZJU-Connect v1.3.1's Setup has no context of its own. Run it in a
	// goroutine so that stopping an access point does not wait for a login
	// that may take minutes; the goroutine is closed when Setup returns.
	type setupResult struct {
		data []byte
		err  error
	}
	done := make(chan setupResult, 1)
	go func() {
		data, err := client.Setup(atrustclient.SetupOptions{
			ServerAddress:            point.Server,
			ServerPort:               point.Port,
			LoginMethod:              loginMethod,
			TOTPSecret:               creds.TOTP,
			ClientData:               clientData,
			ResourceData:             resourceData,
			BestNodesRefreshInterval: 90 * time.Second,
		})
		if err != nil && resumeSID != "" {
			// The saved session is stale: fall back to authenticating with the
			// saved cookies, which still avoids a fresh QR code when possible.
			zjuLog.Printf("[%s] 复用会话失败，改用已保存的凭据重新认证：%v", point.Name, err)
			client.Close()
			client = atrustclient.NewClient(atrustclient.ClientOptions{
				Session:        atrustclient.SessionOptions{Username: point.Username},
				UnderlayDialer: under,
			})
			data, err = client.Setup(atrustclient.SetupOptions{
				ServerAddress:            point.Server,
				ServerPort:               point.Port,
				LoginMethod:              loginMethod,
				TOTPSecret:               creds.TOTP,
				ClientData:               clientData,
				BestNodesRefreshInterval: 90 * time.Second,
			})
		}
		done <- setupResult{data: data, err: err}
	}()

	var authData []byte
	select {
	case <-ctx.Done():
		go func() {
			<-done
			client.Close()
		}()
		return nil, ctx.Err()
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		authData = res.data
	}
	// Always keep the resource data: the global TUN helper resumes the
	// session from it, without logging in again.
	if path, err := writeResourceDump(opts.DataDir, point.ID, client.ResourceData()); err == nil {
		zjuLog.Printf("Saved client resource for %s to %s", point.Name, path)
	} else {
		zjuLog.Printf("Warning: cannot save client resource for %s: %v", point.Name, err)
	}
	if err := writeClientData(opts.DataDir, point.ID, authData); err != nil {
		// A read-only data directory must not stop a working login.
		zjuLog.Printf("Warning: cannot save aTrust client data for %s: %v", point.Name, err)
	}

	ipResources, _ := client.IPResources()
	domainResources, _ := client.DomainResources()
	if skipped := len(point.DisabledApps); skipped > 0 {
		before := len(ipResources)
		ipResources, domainResources = dropDisabledApps(point.DisabledApps, ipResources, domainResources)
		zjuLog.Printf("已按设置停用 %d 个应用：%d 条 IP 资源 → %d 条", skipped, before, len(ipResources))
	}
	dnsResource, _ := client.DNSResource()
	dnsServers, _ := client.DNSServers()

	remoteDNS, dnsErr := client.DNSServer()
	useRemoteDNS := dnsErr == nil && net.ParseIP(remoteDNS) != nil
	if !useRemoteDNS {
		remoteDNS = "10.10.0.21"
	}
	secondary := opts.SecondaryDNS
	if len(dnsServers) > 1 && net.ParseIP(dnsServers[1]) != nil {
		secondary = dnsServers[1]
	}

	vpnStack, err := gvisor.NewStack(client)
	if err != nil {
		return nil, fmt.Errorf("创建 gVisor 网络栈：%w", err)
	}
	resolver := resolve.NewResolver(
		vpnStack, remoteDNS, secondary, opts.DNSTTL,
		domainResources, dnsResource, useRemoteDNS,
	)
	localDNS := service.NewDnsServer(resolver, []string{remoteDNS, secondary})
	vpnStack.SetupResolve(localDNS)
	vpnStack.SetupIPPool(resolver.IPPool)

	sess := &zjuSession{
		client:   client,
		underlay: under,
		stack:    vpnStack,
		resolver: resolver,
		dialer:   dial.NewDialer(vpnStack, resolver, ipResources, false, ""),
		probe:    useRemoteDNS,
		done:     make(chan struct{}),
	}
	sess.info.ClientIP = ipString(client)
	if dns, derr := client.DNSServer(); derr == nil {
		sess.info.DNSServer = dns
	}
	sess.info.BestNodes = bestNodes(client)
	sess.info.NodeGroups = nodeGroups(client)
	sess.info.Apps = appsFromZJU(client.Apps())
	go func() {
		defer func() {
			if r := recover(); r != nil {
				sess.fail(fmt.Errorf("VPN 数据通道中断：%v", r))
			}
		}()
		vpnStack.Run()
		sess.fail(errors.New("VPN 数据通道已关闭"))
	}()

	cleanupUnderlay = false
	cleanupClient = false
	return sess, nil
}

type zjuSession struct {
	client   *atrustclient.Client
	underlay *underlay.Dialer
	stack    *gvisor.Stack
	resolver *resolve.Resolver
	dialer   *dial.Dialer

	info  SessionInfo
	probe bool

	closeOnce sync.Once
	closed    atomic.Bool
	done      chan struct{}
	errMu     sync.Mutex
	err       error
}

func (s *zjuSession) Info() SessionInfo { return s.info }

// ClientData returns the session cookies for the TUN helper, which resumes
// this login instead of making a second one.
func (s *zjuSession) ClientData() ([]byte, error) {
	if s.closed.Load() {
		return nil, errors.New("接入点已断开")
	}
	return s.client.ClientData()
}

// CheckAlive asks the portal whether this login is still the active one. The
// tunnel stays up after another client takes the account over, so this is the
// only way to notice.
func (s *zjuSession) CheckAlive(ctx context.Context) (AliveStatus, error) {
	if s.closed.Load() {
		return AliveStatus{}, errors.New("接入点已断开")
	}
	type result struct {
		status AliveStatus
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		online, err := s.client.CheckOnline()
		res := AliveStatus{
			Username: online.Username,
			Code:     online.Code,
			Message:  online.Message,
			Valid:    err == nil && online.Code == 0,
		}
		ch <- result{res, err}
	}()
	select {
	case r := <-ch:
		return r.status, r.err
	case <-ctx.Done():
		return AliveStatus{}, ctx.Err()
	}
}

func (s *zjuSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.closed.Load() {
		return nil, errors.New("接入点已断开")
	}
	if network != "tcp" {
		return nil, fmt.Errorf("只支持 TCP 连接，收到 %s", network)
	}
	return s.dialer.Dial(ctx, network, addr)
}

// Probe resolves a public name through the VPN's own DNS servers, as
// ZJU-Connect's keep-alive does. The lookup goes through the tunnel and
// keeps the aTrust session alive, so a healthy answer means the session can
// still carry traffic.
func (s *zjuSession) Probe(ctx context.Context) error {
	if s.closed.Load() {
		return errors.New("接入点已断开")
	}
	if !s.probe {
		return nil
	}
	var firstErr error
	try := func(r *net.Resolver) bool {
		if r == nil {
			return false
		}
		lookupCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
		_, err := r.LookupIP(lookupCtx, "ip4", "www.baidu.com")
		cancel()
		if err == nil {
			return true
		}
		if firstErr == nil {
			firstErr = err
		}
		return false
	}
	if udp, err := s.resolver.RemoteUDPResolver(); err == nil && try(udp) {
		return nil
	}
	if tcp, err := s.resolver.RemoteTCPResolver(); err == nil && try(tcp) {
		return nil
	}
	if firstErr == nil {
		firstErr = errors.New("远程 DNS 不可用")
	}
	return firstErr
}

// Done closes when the tunnel ends on its own, and Err says why.
func (s *zjuSession) Done() <-chan struct{} { return s.done }

func (s *zjuSession) Err() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *zjuSession) fail(err error) {
	if s.closed.Load() {
		return
	}
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *zjuSession) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.client.Close()
		s.resolver.Close()
		_ = s.underlay.Close()
		select {
		case <-s.done:
		default:
			close(s.done)
		}
	})
	return nil
}

func readClientData(dir, id string) ([]byte, error) {
	if dir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(clientDataPath(dir, id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 aTrust 客户端数据：%w", err)
	}
	if !json.Valid(data) {
		return nil, nil
	}
	return data, nil
}

func writeClientData(dir, id string, data []byte) error {
	if dir == "" || len(data) == 0 {
		return nil
	}
	path := clientDataPath(dir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".client-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func clientDataPath(dir, id string) string {
	return filepath.Join(dir, "atrust", id+".json")
}

func ipString(client *atrustclient.Client) string {
	ip, err := client.IP()
	if err != nil || ip == nil {
		return ""
	}
	return ip.String()
}

func bestNodes(client *atrustclient.Client) map[string]string {
	client.BestNodesRWMutex.RLock()
	defer client.BestNodesRWMutex.RUnlock()
	out := make(map[string]string, len(client.BestNodes))
	for k, v := range client.BestNodes {
		out[k] = v
	}
	return out
}

func nodeGroups(client *atrustclient.Client) []string {
	out := make([]string, 0, len(client.NodeGroups))
	for group := range client.NodeGroups {
		out = append(out, group)
	}
	return out
}

// guard against a future ZJU-Connect removing the interfaces this file
// relies on.
var (
	_ Session        = (*zjuSession)(nil)
	_ SessionWatcher = (*zjuSession)(nil)
)

// SessionWatcher is a Session that reports when its tunnel ends without
// Close being called.
type SessionWatcher interface {
	Done() <-chan struct{}
	Err() error
}

// savedSessionIDs pulls the session id and device id out of a saved session,
// so Setup can resume it without logging in.
func savedSessionIDs(clientData []byte) (sid, deviceID string) {
	if len(clientData) == 0 {
		return "", ""
	}
	var saved struct {
		Cookies []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"cookies"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(clientData, &saved); err != nil {
		return "", ""
	}
	for _, c := range saved.Cookies {
		if c.Name == "sid" && c.Value != "" {
			sid = c.Value
			break
		}
	}
	return sid, saved.DeviceID
}

// readResourceDump returns the resource list saved with the session, which is
// what lets Setup resume instead of logging in.
func readResourceDump(dir, id string) ([]byte, error) {
	if dir == "" || id == "" {
		return nil, errors.New("nothing to read")
	}
	return os.ReadFile(filepath.Join(dir, "atrust", id+".resource.json"))
}

func writeResourceDump(dir, id string, data []byte) (string, error) {
	if dir == "" || len(data) == 0 {
		return "", errors.New("nothing to dump")
	}
	path := filepath.Join(dir, "atrust", id+".resource.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".resource-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(name, path); err != nil {
		return "", err
	}
	return path, nil
}
