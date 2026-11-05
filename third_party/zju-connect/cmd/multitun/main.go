// Command multitun runs aTrust's native TUN stack for several access points
// in one root process. Each access point gets its own utun, its own resource
// routes and its own fake-IP pool, so a packet is carried by the access point
// that owns it, and internal domains are mapped back to names the way
// zju-connect does it: TUN -> ipPool reverse lookup -> dial by name.
//
// It resumes the sessions the GUI already logged in, using the saved client
// data and resource files, so no second login happens.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tun"
	"github.com/mythologyli/zju-connect/underlay"
)

type pointConfig struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
	SID        string `json:"sid"`
	DeviceID   string `json:"deviceID"`
	ClientData string `json:"clientData"`
	Resource   string `json:"resource"`
	FakeCIDR   string `json:"fakeCIDR"`
	// DisabledApps are application IDs the user took out of the tunnel: their
	// ranges clash with the local network or with another access point.
	DisabledApps []string `json:"disabledApps,omitempty"`
}

type tunConfig struct {
	Points  []pointConfig `json:"points"`
	DNSBind string        `json:"dnsBind"`
}

// hub owns the running stacks, so a new access point can join while the
// others keep their tunnels.
type hub struct {
	mu        sync.Mutex
	points    map[string]*point
	dns       *multiDNS
	accessLog string
	nextIndex int
}

// addDomains records the internal domains a point can resolve, so public
// names go straight to the underlay instead of waiting on a tunnel lookup.
func (h *hub) addDomains(domains map[string][]client.DomainResource) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name := range domains {
		h.dns.addInternalDomain(name)
	}
}

// add starts one access point unless it is already running.
func (h *hub) add(pc pointConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.points[pc.Name]; ok {
		return nil
	}
	index := h.nextIndex
	h.nextIndex++
	p, err := startPoint(pc, h.accessLog, index)
	if err != nil {
		return err
	}
	h.points[pc.Name] = p
	h.dns.Add(p.dns)
	if domains, err := p.client.DomainResources(); err == nil {
		for name := range domains {
			h.dns.addInternalDomain(name)
		}
	}
	log.Printf("point %s ready (fake range %s)", pc.Name, pc.FakeCIDR)
	return nil
}

// count reports how many access points are running.
func (h *hub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.points)
}

// reloadConfig adds the points a new configuration introduced. Points that
// disappeared are left running: tearing a tunnel down and immediately opening
// another for the same session is refused by the server.
func reloadConfig(path string, h *hub) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("reload: read %s: %v", path, err)
		return
	}
	var cfg tunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Printf("reload: parse %s: %v", path, err)
		return
	}
	for _, pc := range cfg.Points {
		if err := h.add(pc); err != nil {
			log.Printf("reload: point %s: %v", pc.Name, err)
			continue
		}
		log.Printf("reload: point %s joined", pc.Name)
	}
}

type point struct {
	cfg    pointConfig
	client *atrustclient.Client
	stack  *tun.Stack
	dns    zcdns.LocalServer
}

func main() {
	// This is a standalone helper: a server SHUTDOWN must end the process so
	// its cleanup (DNS, routes) runs and the GUI can start a fresh one.
	gvisor.ProcessExitOnShutdown = true
	cfgPath := flag.String("config", "", "JSON config with the access points")
	accessLog := flag.String("access-log", "", "file to append access records to")
	logFile := flag.String("log-file", "", "write the helper's log here")
	pidFile := flag.String("pid-file", "", "write the helper's pid here")
	stopFile := flag.String("stop-file", "", "exit when this file appears")
	guiPID := flag.Int("gui-pid", 0, "exit when this process is gone")
	guiFile := flag.String("gui-file", "", "exit when this heartbeat file goes stale")
	reloadFile := flag.String("reload-file", "", "re-read the config when this file appears")
	probeFile := flag.String("probe-file", "", "answer tunnel probes written here")
	flag.Parse()
	if *cfgPath == "" {
		fatal("-config is required")
	}
	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		fatal("read config: %v", err)
	}
	var cfg tunConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fatal("parse config: %v", err)
	}
	if cfg.DNSBind == "" {
		cfg.DNSBind = "127.0.0.1:53"
	}

	// The log belongs to root: a file a previous run created is not writable
	// by the GUI, so the helper owns it and truncates it itself.
	if *logFile != "" {
		if f, ferr := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); ferr == nil {
			log.SetOutput(f)
			os.Stdout = f
			os.Stderr = f
		} else {
			log.Printf("open log %s: %v", *logFile, ferr)
		}
	}

	log.Printf("start: pid=%d config=%q stop=%q pidFile=%q gui=%d",
		os.Getpid(), *cfgPath, *stopFile, *pidFile, *guiPID)

	// Take over from an earlier helper, by pid: matching the command line
	// would match this very process and kill it.
	if *pidFile != "" {
		if b, rerr := os.ReadFile(*pidFile); rerr == nil {
			if old, aerr := strconv.Atoi(strings.TrimSpace(string(b))); aerr == nil && old > 0 && old != os.Getpid() {
				if processAlive(old) {
					terminateProcess(old)
					time.Sleep(300 * time.Millisecond)
				}
			}
		}
		_ = os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
		go func() {
			for {
				time.Sleep(2 * time.Second)
				now := time.Now()
				_ = os.Chtimes(*pidFile, now, now)
			}
		}()
	}
	// Older builds pinned internal names in /etc/hosts with pretend IPs;
	// strip that block so it cannot shadow the resolver below.
	cleanupLegacyHosts()

	// Points are added to the hub one by one: a point logged in later joins
	// without disturbing the tunnels that already work.
	hub := &hub{points: map[string]*point{}, dns: &multiDNS{}, accessLog: *accessLog}
	dnsReady := true
	if err := startDNS(cfg.DNSBind, hub.dns); err != nil {
		dnsReady = false
		log.Printf("DNS %s 无法监听：%v（不改系统 DNS，避免断网）", cfg.DNSBind, err)
	}
	for _, pc := range cfg.Points {
		if err := hub.add(pc); err != nil {
			log.Printf("point %s: %v", pc.Name, err)
		}
	}
	if hub.count() == 0 {
		// Nothing runs, so leave the machine as we found it.
		restoreSystemDNS()
		fatal("no access point could start")
	}
	// A point's stack may take the system DNS over while starting, so claim it
	// again once every point is up — but only if our resolver really listens.
	if dnsReady {
		setSystemDNS("127.0.0.1")
	} else {
		restoreSystemDNS()
	}

	// The GUI adds a point by rewriting the config and touching this file, so
	// an existing tunnel is never torn down for a newcomer.
	if *reloadFile != "" {
		go func() {
			for {
				time.Sleep(500 * time.Millisecond)
				if _, err := os.Stat(*reloadFile); err != nil {
					continue
				}
				_ = os.Remove(*reloadFile)
				log.Printf("reload: config changed, adding new points")
				reloadConfig(*cfgPath, hub)
			}
		}()
	}

	// Probe requests let the GUI test a tunnel for real: a local dial only
	// completes the handshake in the TUN stack and says nothing about whether
	// the aTrust session still carries traffic.
	if *probeFile != "" {
		go serveProbes(*probeFile, hub)
	}

	// Keep the system pointed at our resolver: the aTrust stack's DNS setup
	// can move the service DNS back to the tunnel's own server, which cannot
	// answer internal names for the rest of the system.
	stopGuard := make(chan struct{})
	if dnsReady {
		go guardDNS(stopGuard, "127.0.0.1")
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if *stopFile != "" || *guiPID > 0 || *guiFile != "" {
		go func() {
			for {
				time.Sleep(300 * time.Millisecond)
				if *stopFile != "" {
					if _, err := os.Stat(*stopFile); err == nil {
						if *pidFile != "" {
							_ = os.Remove(*pidFile)
						}
						_ = os.Remove(*stopFile)
						stop <- syscall.SIGTERM
						return
					}
				}
				if *guiFile != "" {
					st, err := os.Stat(*guiFile)
					if err != nil || time.Since(st.ModTime()) > 15*time.Second {
						log.Printf("GUI heartbeat lost, stopping")
						if *pidFile != "" {
							_ = os.Remove(*pidFile)
						}
						stop <- syscall.SIGTERM
						return
					}
				}
				if *guiPID > 0 && !processAlive(*guiPID) {
					if *pidFile != "" {
						_ = os.Remove(*pidFile)
					}
					stop <- syscall.SIGTERM
					return
				}
			}
		}()
	}
	<-stop
	close(stopGuard)
	log.Printf("stopping: restoring DNS")
	restoreSystemDNS()
	log.Printf("stopped")
	log.Println("shutting down")
	hub.mu.Lock()
	for _, p := range hub.points {
		p.client.Close()
	}
	hub.mu.Unlock()
}

// startPoint resumes one access point and starts its TUN stack.
func startPoint(pc pointConfig, accessLog string, index int) (*point, error) {
	clientData, err := os.ReadFile(pc.ClientData)
	if err != nil {
		return nil, fmt.Errorf("read client data: %w", err)
	}
	resourceData, err := os.ReadFile(pc.Resource)
	if err != nil {
		return nil, fmt.Errorf("read resource: %w", err)
	}

	under, err := underlay.New(underlay.Options{AutoDetect: true})
	if err != nil {
		return nil, fmt.Errorf("underlay: %w", err)
	}
	// Reuse the GUI's session instead of logging in again: a second login for
	// the same account makes the server drop the GUI's tunnel, and the two
	// keep kicking each other. The GUI rewrites this file with a fresh SID
	// before starting us, so the saved one is never stale.
	cli := atrustclient.NewClient(atrustclient.ClientOptions{
		Session:        atrustclient.SessionOptions{SID: pc.SID, DeviceID: pc.DeviceID},
		UnderlayDialer: under,
	})
	if _, err := cli.Setup(atrustclient.SetupOptions{
		ServerAddress:            pc.Server,
		ServerPort:               pc.Port,
		ClientData:               clientData,
		ResourceData:             resourceData,
		BestNodesRefreshInterval: 90 * time.Second,
	}); err != nil {
		cli.Close()
		_ = under.Close()
		return nil, fmt.Errorf("setup: %w", err)
	}

	ipResources, _ := cli.IPResources()
	domainResources, _ := cli.DomainResources()
	if len(pc.DisabledApps) > 0 {
		before := len(ipResources)
		ipResources, domainResources = dropDisabledApps(pc.DisabledApps, ipResources, domainResources)
		log.Printf("point %s: 停用 %d 个应用，IP 资源 %d → %d", pc.Name, len(pc.DisabledApps), before, len(ipResources))
	}
	dnsResource, _ := cli.DNSResource()
	remoteDNS, err := cli.DNSServer()
	useRemoteDNS := err == nil && net.ParseIP(remoteDNS) != nil
	if !useRemoteDNS {
		remoteDNS = "10.10.0.21"
	}
	secondary := "114.114.114.114"
	if servers, serr := cli.DNSServers(); serr == nil && len(servers) > 1 && net.ParseIP(servers[1]) != nil {
		secondary = servers[1]
	}

	// Windows gives every stack its own adapter; the name must be unique and
	// free of spaces, because netsh takes it as one argument.
	tun.SetInterfaceName(fmt.Sprintf("aTrustHub%d", index))
	st, err := tun.NewStack(cli, true, true, ipResources)
	if err != nil {
		cli.Close()
		_ = under.Close()
		return nil, fmt.Errorf("tun stack: %w", err)
	}

	res := resolve.NewResolver(st, remoteDNS, secondary, 0, domainResources, dnsResource, useRemoteDNS)
	res.PreferFakeIP = true
	if pc.FakeCIDR != "" {
		if pool, perr := ippool.NewIPPool[[]client.DomainResource](pc.FakeCIDR); perr == nil {
			res.IPPool = pool
		} else {
			log.Printf("point %s: fake pool %s: %v", pc.Name, pc.FakeCIDR, perr)
		}
	}
	local := service.NewDnsServer(res, []string{remoteDNS, secondary})
	st.SetupResolve(local)
	st.SetupIPPool(res.IPPool)

	// Routes: this point's resources, plus its fake-IP range.
	for _, r := range ipResources {
		for _, prefix := range rangePrefixes(r.IPMin, r.IPMax) {
			_ = st.AddRoute(prefix)
		}
	}
	if pc.FakeCIDR != "" {
		_ = st.AddRoute(pc.FakeCIDR)
	}

	if accessLog != "" {
		logger := &accessLogger{path: accessLog, point: pc.Name}
		st.AccessLog = logger.log
	}

	go st.Run()
	return &point{cfg: pc, client: cli, stack: st, dns: local}, nil
}

// accessLogger appends one JSON line per carried connection.
type accessLogger struct {
	path  string
	point string
	mu    sync.Mutex
}

func (l *accessLogger) log(target string, port int, ok bool) {
	rec := fmt.Sprintf(`{"t":%d,"point":%q,"target":%q,"port":%d,"ok":%t}`,
		time.Now().Unix(), l.point, target, port, ok)
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	_, _ = f.WriteString(rec + "\n")
	_ = f.Close()
}

// probeResult is what the GUI reads back from a probe.
type probeResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	MS    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
	// Skip marks a target this helper cannot test (only TCP-tunnel resources
	// can be probed), so the caller does not count it as a failure.
	Skip bool `json:"skip,omitempty"`
}

// serveProbes answers one probe at a time: the request file carries
// "<id>|<point name>|<host:port>", the answer goes to "<file>.result".
func serveProbes(path string, h *hub) {
	resultPath := path + ".result"
	for {
		time.Sleep(200 * time.Millisecond)
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) == 0 {
			continue
		}
		_ = os.Remove(path)
		parts := strings.SplitN(strings.TrimSpace(string(raw)), "|", 3)
		if len(parts) != 3 {
			continue
		}
		res := answerProbe(h, parts[0], parts[1], parts[2])
		b, err := json.Marshal(res)
		if err != nil {
			continue
		}
		_ = os.WriteFile(resultPath, b, 0o644)
	}
}

// answerProbe dials through the named point's own stack, so the result is
// about the aTrust tunnel rather than the local TUN device, which completes
// every handshake by itself.
func answerProbe(h *hub, id, name, addr string) probeResult {
	res := probeResult{ID: id}
	start := time.Now()
	h.mu.Lock()
	p := h.points[name]
	h.mu.Unlock()
	if p == nil {
		res.Error = "接入点未在运行"
		return res
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		res.Error = "地址无效：" + err.Error()
		return res
	}
	ip := net.ParseIP(host)
	if ip == nil {
		res.Error = "保活探测只支持 IP 地址"
		return res
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		res.Error = "端口无效"
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := p.stack.DialTCP(ctx, &net.TCPAddr{IP: ip, Port: port})
	if err != nil {
		if errors.Is(err, client.ErrResourceNotFound) {
			res.Skip = true
			res.Error = "该地址不走 TCP 隧道，无法用连接探测"
			return res
		}
		res.Error = err.Error()
		return res
	}
	_ = conn.Close()
	res.OK = true
	res.MS = time.Since(start).Milliseconds()
	return res
}

// rangePrefixes returns the minimal CIDR blocks covering [lo, hi].
func rangePrefixes(loIP, hiIP net.IP) []string {
	lo := loIP.To4()
	hi := hiIP.To4()
	if lo == nil || hi == nil {
		return nil
	}
	a := uint64(binary.BigEndian.Uint32(lo))
	b := uint64(binary.BigEndian.Uint32(hi))
	if a > b {
		a, b = b, a
	}
	var out []string
	for a <= b {
		bits := 0
		for p := 1; p <= 32; p++ {
			size := uint64(1) << uint(32-p)
			if a%size == 0 && a+size-1 <= b {
				bits = p
				break
			}
		}
		if bits == 0 {
			break
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(a))
		out = append(out, fmt.Sprintf("%s/%d", net.IP(buf[:]).String(), bits))
		size := uint64(1) << uint(32-bits)
		if a+size-1 >= b {
			break
		}
		a += size
	}
	return out
}

// multiDNS asks each point's resolver in turn, so the fake IP a name gets
// belongs to the point that can carry it.
type multiDNS struct {
	mu       sync.Mutex
	servers  []zcdns.LocalServer
	internal map[string]bool
}

// addInternalDomain marks a domain as resolvable through a point.
func (m *multiDNS) addInternalDomain(name string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return
	}
	m.mu.Lock()
	if m.internal == nil {
		m.internal = map[string]bool{}
	}
	m.internal[name] = true
	m.mu.Unlock()
}

// isInternal reports whether a name belongs to an access point.
func (m *multiDNS) isInternal(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	m.mu.Lock()
	defer m.mu.Unlock()
	for domain := range m.internal {
		d := strings.TrimPrefix(domain, "*.")
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

// Add makes a resolver answer through this listener from now on.
func (m *multiDNS) Add(server zcdns.LocalServer) {
	m.mu.Lock()
	m.servers = append(m.servers, server)
	m.mu.Unlock()
}

func (m *multiDNS) snapshot() []zcdns.LocalServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]zcdns.LocalServer(nil), m.servers...)
}

func (m *multiDNS) HandleDnsMsg(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	list := m.snapshot()
	if len(msg.Question) > 0 {
		name := msg.Question[0].Name
		// Public names never wait for a tunnel lookup: that lookup can hang,
		// and while it hangs every browser request looks like a dead network.
		if !m.isInternal(name) {
			// Only take a real answer: NXDOMAIN here may just mean the name is
			// internal to a point, and the point resolvers come next.
			if reply, err := forwardUpstream(ctx, msg); err == nil && reply != nil && len(reply.Answer) > 0 {
				return reply, nil
			}
		}
	}
	for _, s := range list {
		reply, err := s.HandleDnsMsg(ctx, msg)
		if err == nil && reply != nil && len(reply.Answer) > 0 {
			return reply, nil
		}
	}
	// Not an internal name: resolve it on the underlay. Going through a point's
	// resolver here used to make ordinary sites (百度、知乎…) fail while TUN was
	// on, because nothing outside the VPN could answer.
	if reply, err := forwardUpstream(ctx, msg); err == nil {
		return reply, nil
	}
	// Nothing internal answered: let the first resolver forward upstream.
	if len(list) > 0 {
		return list[0].HandleDnsMsg(ctx, msg)
	}
	return nil, fmt.Errorf("no resolver")
}

// publicDNS are resolvers reachable without the tunnel.
var publicDNS = []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"}

// forwardUpstream resolves a name outside the VPN, straight over the underlay.
func forwardUpstream(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	q := msg.Copy()
	client := &dns.Client{Timeout: 2 * time.Second}
	for _, addr := range publicDNS {
		reply, _, err := client.ExchangeContext(ctx, q, addr)
		if err == nil && reply != nil {
			return reply, nil
		}
	}
	return nil, fmt.Errorf("no public resolver answered")
}

func (m *multiDNS) CheckDnsHijack(dstIP net.IP) bool { return true }

func startDNS(bind string, servers *multiDNS) error {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		ctx := context.WithValue(context.Background(), resolve.ContextKeyFakeIP, true)
		reply, err := servers.HandleDnsMsg(ctx, req)
		if err != nil || reply == nil {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		reply.Id = req.Id
		_ = w.WriteMsg(reply)
	})
	// Bind before reporting success: pointing the system at a port nobody
	// listens on would look exactly like the network being down.
	conn, err := net.ListenPacket("udp", bind)
	if err != nil {
		return fmt.Errorf("udp %s: %w", bind, err)
	}
	srvUDP := &dns.Server{PacketConn: conn, Handler: handler}
	go func() {
		if err := srvUDP.ActivateAndServe(); err != nil {
			log.Printf("DNS udp %s: %v", bind, err)
		}
	}()
	srvTCP := &dns.Server{Addr: bind, Net: "tcp", Handler: handler}
	go func() {
		if err := srvTCP.ListenAndServe(); err != nil {
			log.Printf("DNS tcp %s: %v", bind, err)
		}
	}()
	log.Printf("DNS listening on %s", bind)
	return nil
}

// guardDNS keeps every network service pointed at addr while TUN is up.
func guardDNS(stop <-chan struct{}, addr string) {
	ticker := time.NewTicker(dnsGuardInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !systemDNSIs(addr) {
				log.Printf("dns guard: system DNS moved away, setting %s", addr)
				setSystemDNS(addr)
			}
		}
	}
}

// stripHostsBlock removes the lines between two markers, inclusive.
func stripHostsBlock(path, start, end string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	inside := false
	for _, line := range lines {
		switch {
		case strings.TrimSpace(line) == start:
			inside = true
		case strings.TrimSpace(line) == end:
			inside = false
		case !inside:
			out = append(out, line)
		}
	}
	cleaned := strings.Join(out, "\n")
	if cleaned != string(data) {
		_ = os.WriteFile(path, []byte(cleaned), 0o644)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "multitun: "+format+"\n", args...)
	os.Exit(1)
}

var _ = http.StatusOK
