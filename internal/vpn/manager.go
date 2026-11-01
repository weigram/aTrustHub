// Package vpn logs in to several aTrust access points at once and keeps a
// SOCKS5 proxy for each of them and one aggregate proxy over all.
//
// The ZJU-Connect client is used in process: one client, netstack, resolver
// and dialer per access point. Each login has its own device ID and session,
// so one access point failing or being signed out does not touch the others.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/proxy"
)

// State is where an access point is in its login life.
type State string

const (
	StateOffline    State = "offline"
	StateConnecting State = "connecting"
	StateOnline     State = "online"
	StateError      State = "error"
)

// Label is the state in the words the UI shows.
func (s State) Label() string {
	switch s {
	case StateConnecting:
		return "登录中"
	case StateOnline:
		return "在线"
	case StateError:
		return "失败"
	default:
		return "未登录"
	}
}

// Credentials are what the secret store holds for an access point.
type Credentials struct {
	Login string
	TOTP  string
	// ExternalLogin shows loginURL to the user, as a QR code or a browser
	// page, and returns the https callback URL the identity provider
	// redirects to. It is what the WeCom (external OAuth2/CAS) mode uses;
	// the password mode leaves it nil.
	ExternalLogin func(ctx context.Context, loginURL string) (string, error)
}

// Session is one logged-in access point.
type Session interface {
	// Dial opens a connection through the VPN tunnel.
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve resolves a name through the tunnel, for internal domains.
	// Info describes the session for the UI.
	Info() SessionInfo
	// Close logs out and releases the tunnel.
	Close() error
}

// SessionInfo is what a Session reports about itself.
type SessionInfo struct {
	ClientIP     string
	DNSServer    string
	NodeGroups   []string
	BestNodes    map[string]string
	HealthTarget string
	Apps         []App
}

// Connector logs in to one access point. It blocks until the login either
// succeeds or fails, and must honor ctx.
type Connector func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error)

// CredentialFunc reads the stored creds of an access point.
type CredentialFunc func(id string) (Credentials, error)

// View is a copy of one access point's state for the UI.
type View struct {
	ID          string
	Name        string
	Server      string
	Port        int
	Username    string
	AuthMode    string
	LoginDomain string
	SocksPort   int
	InPool      bool
	AutoConnect bool

	State      State
	Error      string
	ClientIP   string
	DNSServer  string
	NodeGroups []string
	BestNodes  map[string]string
	Apps       []App

	Active int64
	Total  int64
	Failed int64

	// Latency is the recent successful dial time through this point.
	Latency time.Duration
	// LoginDuration is how long the last successful login took.
	LoginDuration time.Duration
}

// Endpoint is the public address of the aggregate proxy.
type Endpoint struct {
	Addr    string
	Running bool
	Error   string
}

// Manager owns the access points and their proxies.
type Manager struct {
	mu sync.RWMutex
	// failMu guards the access-log de-duplication fields below.
	failMu     sync.Mutex
	lastFail   string
	lastFailAt time.Time
	order      []string
	points     map[string]*endpoint
	settings   model.Settings

	connector Connector
	creds     CredentialFunc
	bus       *LogBus
	notify    func()

	aggregate    *proxy.Server
	aggregateErr string

	rr atomic.Uint64

	healthStop chan struct{}
	healthWG   sync.WaitGroup

	started bool
	closed  bool
}

type endpoint struct {
	cfg model.AccessPoint

	state  State
	errMsg string
	info   SessionInfo
	sess   Session
	proxy  *proxy.Server
	gen    int
	cancel context.CancelFunc

	active atomic.Int64
	total  atomic.Int64
	failed atomic.Int64
	// latencyNS is an exponential moving average of successful dials.
	latencyNS atomic.Int64
	// login is how long the current login took.
	login time.Duration
	// probeFails counts consecutive health probes that failed.
	probeFails int
}

// NewManager returns a manager that uses connector to log in and creds to
// read secrets. notify runs after every state change, and may be nil.
func NewManager(connector Connector, creds CredentialFunc, bus *LogBus, notify func()) *Manager {
	m := &Manager{
		points:     map[string]*endpoint{},
		settings:   model.DefaultSettings(),
		connector:  connector,
		creds:      creds,
		bus:        bus,
		notify:     notify,
		healthStop: make(chan struct{}),
	}
	m.healthWG.Add(1)
	go m.healthLoop()
	return m
}

func (m *Manager) changed() {
	if m.notify != nil {
		m.notify()
	}
}

func (m *Manager) logf(format string, args ...any) {
	if m.bus != nil {
		m.bus.Add("app", fmt.Sprintf(format, args...))
	}
}

// Start opens the aggregate proxy if it is enabled and logs in the access
// points set to connect automatically (those with "自动登录" checked).
func (m *Manager) Start() {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	m.restartAggregate()
	m.ConnectAll(true)
}

// Apply makes the manager match cfg: it adds new points, updates existing
// ones, removes those gone, and restarts what has to restart.
func (m *Manager) Apply(cfg model.Config) {
	var closes []closeLater
	var restarts []string

	m.mu.Lock()
	old := m.settings
	m.settings = cfg.Settings

	seen := make(map[string]bool, len(cfg.Points))
	for _, p := range cfg.Points {
		seen[p.ID] = true
		ep := m.points[p.ID]
		if ep == nil {
			ep = &endpoint{cfg: p}
			m.points[p.ID] = ep
			m.order = append(m.order, p.ID)
			continue
		}
		oldCfg := ep.cfg
		ep.cfg = p
		if ep.state != StateOffline && needsRestart(oldCfg, p) {
			restarts = append(restarts, p.ID)
			m.stopEndpointLocked(p.ID, &closes)
		}
	}
	for id := range m.points {
		if seen[id] {
			continue
		}
		m.stopEndpointLocked(id, &closes)
		delete(m.points, id)
	}
	order := m.order[:0]
	for _, id := range m.order {
		if _, ok := m.points[id]; ok {
			order = append(order, id)
		}
	}
	m.order = order

	aggregateChanged := m.started && (old.ListenHost != cfg.Settings.ListenHost ||
		old.AggregatePort != cfg.Settings.AggregatePort ||
		old.AggregateEnabled != cfg.Settings.AggregateEnabled)
	m.mu.Unlock()

	for _, c := range closes {
		if c.proxy != nil {
			_ = c.proxy.Close()
		}
		if c.sess != nil {
			_ = c.sess.Close()
		}
	}
	if aggregateChanged {
		m.restartAggregate()
	}
	for _, id := range restarts {
		go m.Reconnect(id)
	}
	m.changed()
}

func needsRestart(a, b model.AccessPoint) bool {
	return a.Server != b.Server || a.Port != b.Port ||
		a.Username != b.Username || a.AuthMode != b.AuthMode ||
		a.LoginDomain != b.LoginDomain || a.SocksPort != b.SocksPort
}

type closeLater struct {
	sess  Session
	proxy *proxy.Server
}

func (m *Manager) stopEndpointLocked(id string, closes *[]closeLater) {
	ep := m.points[id]
	if ep == nil {
		return
	}
	ep.gen++
	ep.state = StateOffline
	ep.errMsg = ""
	ep.info = SessionInfo{}
	if ep.cancel != nil {
		ep.cancel()
		ep.cancel = nil
	}
	sess, p := ep.sess, ep.proxy
	ep.sess, ep.proxy = nil, nil
	if sess != nil || p != nil {
		*closes = append(*closes, closeLater{sess: sess, proxy: p})
	}
}

// Close stops every login, both proxies and the health loop.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.started = false
	m.mu.Unlock()

	close(m.healthStop)
	healthDone := make(chan struct{})
	go func() {
		m.healthWG.Wait()
		close(healthDone)
	}()
	select {
	case <-healthDone:
	case <-time.After(2 * time.Second):
		// A probe is still in flight; it checks m.closed before it acts.
	}

	var closes []closeLater
	m.mu.Lock()
	for id := range m.points {
		m.stopEndpointLocked(id, &closes)
	}
	p := m.aggregate
	m.aggregate = nil
	m.mu.Unlock()
	for _, c := range closes {
		if c.proxy != nil {
			_ = c.proxy.Close()
		}
		if c.sess != nil {
			_ = c.sess.Close()
		}
	}
	if p != nil {
		_ = p.Close()
	}
}

// Views returns the access points in the order of the list.
func (m *Manager) Views() []View {
	m.mu.RLock()
	defer m.mu.RUnlock()
	views := make([]View, 0, len(m.order))
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil {
			continue
		}
		v := View{
			ID: ep.cfg.ID, Name: ep.cfg.Name, Server: ep.cfg.Server,
			Port: ep.cfg.Port, Username: ep.cfg.Username,
			AuthMode: ep.cfg.AuthMode, LoginDomain: ep.cfg.LoginDomain,
			SocksPort: ep.cfg.SocksPort,
			InPool:    ep.cfg.InPool, AutoConnect: ep.cfg.AutoConnect,
			State: ep.state, Error: ep.errMsg, ClientIP: ep.info.ClientIP,
			NodeGroups: append([]string(nil), ep.info.NodeGroups...),
			BestNodes:  cloneMap(ep.info.BestNodes),
			Apps:       cloneApps(ep.info.Apps),
			Active:     ep.active.Load(), Total: ep.total.Load(),
			Failed:  ep.failed.Load(),
			Latency: time.Duration(ep.latencyNS.Load()),
		}
		views = append(views, v)
	}
	return views
}

// View returns one access point's state.
func (m *Manager) View(id string) (View, bool) {
	for _, v := range m.Views() {
		if v.ID == id {
			return v, true
		}
	}
	return View{}, false
}

// Counts returns how many access points are online, connecting and total.
func (m *Manager) Counts() (online, connecting, total int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, ep := range m.points {
		total++
		switch ep.state {
		case StateOnline:
			online++
		case StateConnecting:
			connecting++
		}
	}
	return
}

// Connect starts the login of one access point in the background. It does
// nothing when the point is already online or logging in.
func (m *Manager) Connect(id string) {
	m.mu.Lock()
	ep := m.points[id]
	if ep == nil || ep.state == StateOnline || ep.state == StateConnecting {
		m.mu.Unlock()
		return
	}
	if m.closed {
		m.mu.Unlock()
		return
	}
	ep.gen++
	gen := ep.gen
	ep.state = StateConnecting
	ep.errMsg = ""
	m.mu.Unlock()
	m.changed()

	go m.connect(id, gen)
}

func (m *Manager) connect(id string, gen int) {
	m.mu.RLock()
	ep := m.points[id]
	if ep == nil {
		m.mu.RUnlock()
		return
	}
	cfg := ep.cfg
	m.mu.RUnlock()

	creds := Credentials{}
	if m.creds != nil {
		var err error
		creds, err = m.creds(id)
		if err != nil && !errors.Is(err, ErrNoCredentials) {
			m.fail(id, gen, fmt.Sprintf("读取凭据失败：%v", err))
			return
		}
	}
	switch model.AuthMode(cfg.AuthMode) {
	case model.AuthModeWeCom:
		if creds.ExternalLogin == nil {
			m.fail(id, gen, "扫码登录窗口不可用")
			return
		}
	case model.AuthModeAuto:
		if strings.TrimSpace(creds.Login) == "" && creds.ExternalLogin == nil {
			m.fail(id, gen, "自动识别需要密码或扫码登录窗口")
			return
		}
	default:
		if strings.TrimSpace(creds.Login) == "" {
			m.fail(id, gen, "没有保存密码：先编辑接入点填上密码")
			return
		}
	}

	m.logf("[%s] 正在登录 %s:%d …", cfg.Name, cfg.Server, cfg.Port)
	ctx, cancel := context.WithCancel(context.Background())
	ctx, timeout := context.WithTimeout(ctx, 5*time.Minute)
	defer timeout()
	m.mu.Lock()
	if cur := m.points[id]; cur != nil && cur.gen == gen {
		cur.cancel = cancel
	}
	m.mu.Unlock()
	defer cancel()

	start := time.Now()
	sess, err := m.callConnector(ctx, cfg, creds)
	if err != nil {
		m.fail(id, gen, friendlyConnectError(err))
		return
	}

	var p *proxy.Server
	if cfg.SocksPort > 0 {
		p, err = m.newProxy(cfg, ep, func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sess.Dial(ctx, network, addr)
		})
		if err != nil {
			_ = sess.Close()
			m.fail(id, gen, fmt.Sprintf("SOCKS5 端口 %d 无法监听：%v", cfg.SocksPort, err))
			return
		}
	}

	m.mu.Lock()
	cur := m.points[id]
	if cur == nil || cur.gen != gen || cur.state != StateConnecting {
		m.mu.Unlock()
		if p != nil {
			_ = p.Close()
		}
		_ = sess.Close()
		return
	}
	cur.sess = sess
	cur.proxy = p
	cur.cancel = nil
	cur.state = StateOnline
	cur.errMsg = ""
	cur.info = sess.Info()
	cur.probeFails = 0
	cur.login = time.Since(start)
	m.mu.Unlock()

	m.logf("[%s] 已登录，用时 %s，隧道地址 %s", cfg.Name, time.Since(start).Round(time.Millisecond), sess.Info().ClientIP)
	m.changed()
	m.watch(id, gen, sess)
}

// watch notices a tunnel that ends by itself, as when the server signs the
// session out, and logs the point back in when the settings allow it.
func (m *Manager) watch(id string, gen int, sess Session) {
	w, ok := sess.(SessionWatcher)
	if !ok {
		return
	}
	<-w.Done()
	m.mu.Lock()
	cur := m.points[id]
	if cur == nil || cur.gen != gen || cur.state != StateOnline || cur.sess != sess {
		m.mu.Unlock()
		return
	}
	auto := m.settings.AutoReconnect
	name := cur.cfg.Name
	msg := "连接已被服务器断开"
	if err := w.Err(); err != nil {
		msg = err.Error()
	}
	cur.state = StateError
	cur.errMsg = msg
	p := cur.proxy
	cur.proxy = nil
	cur.sess = nil
	cur.info = SessionInfo{}
	m.mu.Unlock()

	if p != nil {
		_ = p.Close()
	}
	_ = sess.Close()
	m.logf("[%s] %s", name, msg)
	m.changed()
	if auto {
		m.reconnectAfter(id, 5*time.Second)
	}
}

// reconnectAfter logs a point back in after a pause, unless the user
// changed its state meanwhile.
func (m *Manager) reconnectAfter(id string, delay time.Duration) {
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-m.healthStop:
			return
		case <-timer.C:
		}
		m.mu.RLock()
		ep := m.points[id]
		ok := ep != nil && ep.state == StateError && !m.closed
		m.mu.RUnlock()
		if ok {
			m.Connect(id)
		}
	}()
}

func (m *Manager) callConnector(ctx context.Context, cfg model.AccessPoint, creds Credentials) (sess Session, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("登录过程崩溃：%v", r)
		}
	}()
	return m.connector(ctx, cfg, creds)
}

func (m *Manager) fail(id string, gen int, msg string) {
	m.mu.Lock()
	cur := m.points[id]
	if cur == nil || cur.gen != gen {
		m.mu.Unlock()
		return
	}
	cur.state = StateError
	cur.errMsg = msg
	cur.cancel = nil
	name := cur.cfg.Name
	m.mu.Unlock()
	m.logf("[%s] 登录失败：%s", name, msg)
	m.changed()
}

// Disconnect logs one access point out.
func (m *Manager) Disconnect(id string) {
	var closes []closeLater
	m.mu.Lock()
	m.stopEndpointLocked(id, &closes)
	m.mu.Unlock()
	for _, c := range closes {
		if c.proxy != nil {
			_ = c.proxy.Close()
		}
		if c.sess != nil {
			_ = c.sess.Close()
		}
	}
	m.changed()
}

// Reconnect logs a point out and in again.
func (m *Manager) Reconnect(id string) {
	m.Disconnect(id)
	m.Connect(id)
}

// ConnectAll logs in every access point, or only those set to connect
// automatically.
func (m *Manager) ConnectAll(autoOnly bool) int {
	m.mu.RLock()
	ids := make([]string, 0, len(m.order))
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil || ep.state == StateOnline || ep.state == StateConnecting {
			continue
		}
		if autoOnly && !ep.cfg.AutoConnect {
			continue
		}
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	for _, id := range ids {
		m.Connect(id)
	}
	return len(ids)
}

// DisconnectAll logs every access point out.
func (m *Manager) DisconnectAll() {
	m.mu.RLock()
	ids := make([]string, 0, len(m.order))
	for _, id := range m.order {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	for _, id := range ids {
		m.Disconnect(id)
	}
}

func (m *Manager) newProxy(cfg model.AccessPoint, ep *endpoint, dial func(context.Context, string, string) (net.Conn, error)) (*proxy.Server, error) {
	m.mu.RLock()
	host := m.settings.ListenHost
	m.mu.RUnlock()
	p := proxy.New(proxy.Options{
		Addr: net.JoinHostPort(host, fmt.Sprint(cfg.SocksPort)),
		Dial: dial,
		OnConnect: func() {
			ep.total.Add(1)
			ep.active.Add(1)
		},
		OnClose: func() {
			ep.active.Add(-1)
		},
		Logf: func(format string, args ...any) {
			m.logf("[%s] "+format, append([]any{cfg.Name}, args...)...)
		},
	})
	if err := p.Start(); err != nil {
		return nil, err
	}
	return p, nil
}

// Aggregate returns the state of the aggregate proxy.
func (m *Manager) Aggregate() Endpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.aggregate == nil {
		return Endpoint{Error: m.aggregateErr}
	}
	addr := m.aggregate.Addr()
	if addr == nil {
		return Endpoint{Error: m.aggregateErr}
	}
	return Endpoint{Addr: addr.String(), Running: true}
}

func (m *Manager) restartAggregate() {
	m.mu.Lock()
	old := m.aggregate
	m.aggregate = nil
	m.aggregateErr = ""
	settings := m.settings
	m.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	if !settings.AggregateEnabled {
		return
	}
	addr := net.JoinHostPort(settings.ListenHost, fmt.Sprint(settings.AggregatePort))
	p := proxy.New(proxy.Options{
		Addr: addr,
		Dial: m.Dial,
		Logf: func(format string, args ...any) {
			m.logf("[统一入口] "+format, args...)
		},
	})
	if err := p.Start(); err != nil {
		m.mu.Lock()
		m.aggregateErr = err.Error()
		m.mu.Unlock()
		m.logf("统一入口监听失败：%v（端口可能被旧实例或别的程序占用，可在设置里换端口）", err)
		m.changed()
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = p.Close()
		return
	}
	m.aggregate = p
	m.mu.Unlock()
	m.logf("统一入口在 %s 监听，分流模式：%s", addr, settings.Routing.Label())
	m.changed()
}

// candidate is one online access point the aggregate proxy may use.
type candidate struct {
	id   string
	name string
	sess Session
	apps []App
}

func (m *Manager) online() []candidate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]candidate, 0, len(m.order))
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil || ep.state != StateOnline || ep.sess == nil || !ep.cfg.InPool {
			continue
		}
		out = append(out, candidate{id: id, name: ep.cfg.Name, sess: ep.sess, apps: ep.info.Apps})
	}
	return out
}

// Dial picks an access point and opens the connection through it, moving
// to the next one when a dial fails. It is the Dial of the aggregate proxy.
func (m *Manager) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	m.mu.RLock()
	mode := m.settings.Routing
	m.mu.RUnlock()

	pool := m.online()
	if len(pool) == 0 {
		err := errors.New("没有在线的接入点")
		m.logAccessFail(addr, "", err)
		return nil, err
	}
	// Prefer the access point that actually owns this target address (its
	// published apps cover it). Without this, failover/latency picks a point
	// whose tunnel has no route for the target, and the dial goes DIRECT and
	// times out even though the right point would reach it.
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		host = addr
	}
	if host != "" {
		owned := make([]candidate, 0, len(pool))
		others := make([]candidate, 0, len(pool))
		for _, c := range pool {
			if candidateCovers(c, host) {
				owned = append(owned, c)
			} else {
				others = append(others, c)
			}
		}
		if len(owned) > 0 {
			pool = append(owned, others...)
			m.logf("按资源路由 %s -> %s", host, owned[0].name)
		}
	}
	if mode == model.RoutingHash {
		start := int(hashHost(host)) % len(pool)
		pool = append(append([]candidate(nil), pool[start:]...), pool[:start]...)
	}

	tried := map[string]bool{}
	var lastErr error
	attempts := len(pool)
	if attempts > 3 {
		attempts = 3
	}
	for i := 0; i < attempts; i++ {
		c, ok := m.pick(pool, mode, tried)
		if !ok {
			break
		}
		tried[c.id] = true

		start := time.Now()
		conn, err := safeDial(ctx, c.sess, network, addr)
		if err == nil {
			m.recordSuccess(c.id, time.Since(start))
			m.logAccess(host, addr, c)
			return conn, nil
		}
		lastErr = err
		m.recordFailure(c.id)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		m.logf("[%s] 连接 %s 失败，尝试下一个接入点：%v", c.name, addr, err)
		m.logAccessFail(addr, c.name, err)
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的接入点")
	}
	m.logAccessFail(addr, "", lastErr)
	return nil, lastErr
}

// candidateCovers reports whether c's published apps include host.
func candidateCovers(c candidate, host string) bool {
	_, ok := candidateMatchApp(c, host)
	return ok
}

// candidateMatchApp returns the name of c's app that covers host, if any.
func candidateMatchApp(c candidate, host string) (string, bool) {
	for _, app := range c.apps {
		if app.Covers(host) {
			return app.Name, true
		}
	}
	return "", false
}

// Access log sources. The view shows a green dot for AccessOK and a red one
// for AccessFail.
const (
	AccessOK   = "访问"
	AccessFail = "访问失败"
)

// logAccess records one proxied connection with the access point and app it
// went through, for the access log.
func (m *Manager) logAccess(host, addr string, c candidate) {
	appName, ok := candidateMatchApp(c, host)
	if ok && appName != "" {
		m.bus.Upsert(AccessOK, fmt.Sprintf("%s → %s ｜ 应用：%s", addr, c.name, appName))
		return
	}
	m.bus.Upsert(AccessOK, fmt.Sprintf("%s → %s", addr, c.name))
}

// logAccessFail records one failed attempt at opening a connection,
// collapsing repeats of the same target/point within a second.
func (m *Manager) logAccessFail(addr, point string, err error) {
	reason := "连接失败"
	if err != nil {
		reason = err.Error()
	}
	if len(reason) > 80 {
		reason = reason[:80] + "…"
	}
	line := fmt.Sprintf("%s ｜ %s", addr, reason)
	if point != "" {
		line = fmt.Sprintf("%s ｜ %s ｜ %s", addr, point, reason)
	}
	m.bus.Upsert(AccessFail, line)
}

func (m *Manager) pick(pool []candidate, mode model.Routing, tried map[string]bool) (candidate, bool) {
	avail := make([]candidate, 0, len(pool))
	for _, c := range pool {
		if !tried[c.id] {
			avail = append(avail, c)
		}
	}
	if len(avail) == 0 {
		return candidate{}, false
	}
	switch mode {
	case model.RoutingFailover:
		return avail[0], true
	case model.RoutingRoundRobin:
		return avail[int(m.rr.Add(1)-1)%len(avail)], true
	case model.RoutingHash:
		return avail[0], true
	default: // latency
		// Points that have not dialed yet get one turn each, so all of
		// them have a measurement before the fastest wins.
		unknown := make([]candidate, 0, len(avail))
		for _, c := range avail {
			if m.latencyOf(c.id) <= 0 {
				unknown = append(unknown, c)
			}
		}
		if len(unknown) > 0 {
			return unknown[int(m.rr.Add(1)-1)%len(unknown)], true
		}
		best := avail[0]
		bestNS := m.latencyOf(best.id)
		for _, c := range avail[1:] {
			if ns := m.latencyOf(c.id); ns < bestNS {
				best, bestNS = c, ns
			}
		}
		return best, true
	}
}

func (m *Manager) latencyOf(id string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ep := m.points[id]; ep != nil {
		if ns := ep.latencyNS.Load(); ns > 0 {
			return ns
		}
	}
	// A point that has not dialed yet is unknown, not slow.
	return 0
}

func (m *Manager) recordSuccess(id string, d time.Duration) {
	m.mu.Lock()
	ep := m.points[id]
	if ep == nil {
		m.mu.Unlock()
		return
	}
	old := ep.latencyNS.Load()
	if old == 0 {
		ep.latencyNS.Store(int64(d))
	} else {
		// 7/8 of the old value and 1/8 of this one, in nanoseconds.
		ep.latencyNS.Store(old - old/8 + int64(d)/8)
	}
	m.mu.Unlock()
}

func (m *Manager) recordFailure(id string) {
	m.mu.Lock()
	if ep := m.points[id]; ep != nil {
		ep.failed.Add(1)
	}
	m.mu.Unlock()
}

func safeDial(ctx context.Context, sess Session, network, addr string) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("VPN 连接崩溃：%v", r)
		}
	}()
	return sess.Dial(ctx, network, addr)
}

func hashHost(host string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(host); i++ {
		h ^= uint32(host[i])
		h *= 16777619
	}
	return h
}

func (m *Manager) healthLoop() {
	defer m.healthWG.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	last := time.Time{}
	for {
		select {
		case <-m.healthStop:
			return
		case now := <-ticker.C:
			m.mu.RLock()
			interval := m.settings.HealthIntervalSec
			auto := m.settings.AutoReconnect
			m.mu.RUnlock()
			if interval <= 0 {
				continue
			}
			if !last.IsZero() && now.Sub(last) < time.Duration(interval)*time.Second {
				continue
			}
			last = now
			m.probeAll(auto)
		}
	}
}

func (m *Manager) probeAll(autoReconnect bool) {
	type probe struct {
		id     string
		name   string
		sess   Session
		target string
	}
	var probes []probe
	m.mu.RLock()
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil || ep.state != StateOnline || ep.sess == nil {
			continue
		}
		if _, ok := ep.sess.(Prober); !ok && ep.info.HealthTarget == "" {
			continue
		}
		probes = append(probes, probe{id: id, name: ep.cfg.Name, sess: ep.sess, target: ep.info.HealthTarget})
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	for _, p := range probes {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			err := probeSession(ctx, p.sess, p.target)
			cancel()
			if err == nil {
				m.mu.Lock()
				if ep := m.points[p.id]; ep != nil {
					ep.probeFails = 0
				}
				m.mu.Unlock()
				return
			}
			dead := false
			name := p.name
			m.mu.Lock()
			if ep := m.points[p.id]; ep != nil && ep.state == StateOnline {
				ep.probeFails++
				if ep.probeFails >= 3 && autoReconnect {
					dead = true
				}
			}
			m.mu.Unlock()
			if dead {
				m.logf("[%s] 连续三次健康检查失败，重新登录", name)
				m.Disconnect(p.id)
				m.reconnectAfter(p.id, 5*time.Second)
			}
		}()
	}
	wg.Wait()
}

// Prober is a Session that can check its own tunnel.
type Prober interface {
	Probe(ctx context.Context) error
}

func probeSession(ctx context.Context, sess Session, target string) error {
	if p, ok := sess.(Prober); ok {
		return p.Probe(ctx)
	}
	conn, err := safeDial(ctx, sess, "tcp", target)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ErrNoCredentials means an access point has no stored 口令.
var ErrNoCredentials = errors.New("no credentials")

func friendlyConnectError(err error) string {
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "登录超时：服务器没有响应，检查地址、端口和网络"
	case errors.Is(err, context.Canceled):
		return "登录已取消"
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "graph") || strings.Contains(lower, "captcha"):
		return "服务器要求图形验证码，这个版本还不支持：" + msg
	case strings.Contains(lower, "auth") && strings.Contains(lower, "failed"):
		return "用户名或密码错误：" + msg
	}
	return msg
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// NodeSummary returns the node groups of a view as sorted "group → node"
// lines, for the UI.
func NodeSummary(v View) []string {
	lines := make([]string, 0, len(v.BestNodes))
	for group, node := range v.BestNodes {
		lines = append(lines, group+" → "+node)
	}
	sort.Strings(lines)
	return lines
}

func cloneApps(in []App) []App {
	if in == nil {
		return nil
	}
	out := make([]App, len(in))
	for i, app := range in {
		out[i] = app
		out[i].Addresses = append([]AppAddress(nil), app.Addresses...)
	}
	return out
}

// TestDialAny tries each addr through one online access point's tunnel and
// returns the first that connects.
func (m *Manager) TestDialAny(id string, addrs []string) (string, time.Duration, error) {
	var lastErr error
	for _, addr := range addrs {
		d, err := m.TestDial(id, "tcp", addr)
		if err == nil {
			return addr, d, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("没有可测试的地址")
	}
	return "", 0, lastErr
}

// TestDial opens a connection to addr through one online access point's
// tunnel, for the app's connectivity check. It does not send data.
func (m *Manager) TestDial(id, network, addr string) (time.Duration, error) {
	return m.TestDialTimeout(id, network, addr, 12*time.Second)
}

// TestDialTimeout is TestDial with an explicit per-attempt timeout.
func (m *Manager) TestDialTimeout(id, network, addr string, timeout time.Duration) (time.Duration, error) {
	m.mu.RLock()
	ep := m.points[id]
	var sess Session
	online := ep != nil && ep.state == StateOnline
	if online {
		sess = ep.sess
	}
	m.mu.RUnlock()
	if !online || sess == nil {
		return 0, errors.New("接入点未在线")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := sess.Dial(ctx, network, addr)
	if err != nil {
		return time.Since(start), err
	}
	_ = conn.Close()
	return time.Since(start), nil
}
