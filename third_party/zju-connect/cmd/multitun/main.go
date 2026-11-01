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
	"strings"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
}

type tunConfig struct {
	Points  []pointConfig `json:"points"`
	DNSBind string        `json:"dnsBind"`
}

type point struct {
	cfg    pointConfig
	client *atrustclient.Client
	stack  *tun.Stack
	dns    zcdns.LocalServer
}

func main() {
	cfgPath := flag.String("config", "", "JSON config with the access points")
	accessLog := flag.String("access-log", "", "file to append access records to")
	logFile := flag.String("log-file", "", "write the helper's log here")
	pidFile := flag.String("pid-file", "", "write the helper's pid here")
	stopFile := flag.String("stop-file", "", "exit when this file appears")
	guiPID := flag.Int("gui-pid", 0, "exit when this process is gone")
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

	// Point the system at our resolver straight away; guardDNS keeps it there.
	setSystemDNS("127.0.0.1")

	var points []*point
	for _, pc := range cfg.Points {
		p, err := startPoint(pc, *accessLog)
		if err != nil {
			log.Printf("point %s: %v", pc.Name, err)
			continue
		}
		points = append(points, p)
		log.Printf("point %s ready (fake range %s)", pc.Name, pc.FakeCIDR)
	}
	if len(points) == 0 {
		fatal("no access point could start")
	}

	// One DNS listener answers for every point: it asks each point's resolver
	// in turn, and the fake IP it returns belongs to that point's range, so
	// the route picks the right tunnel.
	servers := make([]zcdns.LocalServer, 0, len(points))
	for _, p := range points {
		servers = append(servers, p.dns)
	}
	startDNS(cfg.DNSBind, servers)
	// A point's stack may take the system DNS over while starting, so claim it
	// again once every point is up.
	setSystemDNS("127.0.0.1")

	// Keep the system pointed at our resolver: the aTrust stack's DNS setup
	// can move the service DNS back to the tunnel's own server, which cannot
	// answer internal names for the rest of the system.
	stopGuard := make(chan struct{})
	go guardDNS(stopGuard, "127.0.0.1")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	if *stopFile != "" || *guiPID > 0 {
		go func() {
			for {
				time.Sleep(time.Second)
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
				if *guiPID > 0 && !processAlive(*guiPID) {
					stop <- syscall.SIGTERM
					return
				}
			}
		}()
	}
	<-stop
	close(stopGuard)
	restoreSystemDNS()
	log.Println("shutting down")
	for _, p := range points {
		p.client.Close()
	}
}

// startPoint resumes one access point and starts its TUN stack.
func startPoint(pc pointConfig, accessLog string) (*point, error) {
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
	cli := atrustclient.NewClient(atrustclient.ClientOptions{
		Session: atrustclient.SessionOptions{SID: pc.SID, DeviceID: pc.DeviceID},
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

	st, err := tun.NewStack(cli, true, true, ipResources)
	if err != nil {
		cli.Close()
		_ = under.Close()
		return nil, fmt.Errorf("tun stack: %w", err)
	}

	res := resolve.NewResolver(st, remoteDNS, secondary, 0, domainResources, dnsResource, useRemoteDNS)
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
	servers []zcdns.LocalServer
}

func (m *multiDNS) HandleDnsMsg(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	for _, s := range m.servers {
		reply, err := s.HandleDnsMsg(ctx, msg)
		if err == nil && reply != nil && len(reply.Answer) > 0 {
			return reply, nil
		}
	}
	// Nothing internal answered: let the first resolver forward upstream.
	if len(m.servers) > 0 {
		return m.servers[0].HandleDnsMsg(ctx, msg)
	}
	return nil, fmt.Errorf("no resolver")
}

func (m *multiDNS) CheckDnsHijack(dstIP net.IP) bool { return true }

func startDNS(bind string, servers []zcdns.LocalServer) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		ctx := context.WithValue(context.Background(), resolve.ContextKeyFakeIP, true)
		reply, err := (&multiDNS{servers: servers}).HandleDnsMsg(ctx, req)
		if err != nil || reply == nil {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			_ = w.WriteMsg(m)
			return
		}
		reply.Id = req.Id
		_ = w.WriteMsg(reply)
	})
	go func() {
		_ = (&dns.Server{Addr: bind, Net: "udp", Handler: handler}).ListenAndServe()
	}()
	go func() {
		_ = (&dns.Server{Addr: bind, Net: "tcp", Handler: handler}).ListenAndServe()
	}()
	log.Printf("DNS listening on %s", bind)
}

// guardDNS keeps every network service pointed at addr while TUN is up.
func guardDNS(stop <-chan struct{}, addr string) {
	ticker := time.NewTicker(2 * time.Second)
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
