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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	atrustclient "github.com/mythologyli/zju-connect/client/atrust"

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

	State  State
	Error  string
	// MonitorOn, MonitorInterval, Alive and AliveErr describe the session
	// validity check of this point.
	MonitorOn       bool
	MonitorInterval int
	Alive           string
	AliveAt         int64
	AliveErr        string
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

	// dataDir is where saved sessions live, used to probe a login whose
	// tunnel is owned by the TUN helper.
	dataDir string
	healthStop chan struct{}
	// monitorStop ends the session validity loop.
	monitorStop chan struct{}
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
	// tunServed means the global TUN owns this point's tunnel and the GUI has
	// handed its own session over.
	tunServed bool
	// 会话有效性监测状态。
	aliveAt    time.Time
	aliveState string
	aliveErr   string
	aliveFails int
	// aliveRetryAt schedules an early recheck after one bad answer, so a
	// single hiccup does not wait out the whole interval.
	aliveRetryAt time.Time
	// retryStep counts login retries after the session was taken over.
	retryStep int
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
		healthStop:  make(chan struct{}),
		monitorStop: make(chan struct{}),
	}
	m.healthWG.Add(1)
	go m.healthLoop()
	go m.monitorLoop()
	return m
}

// SetDataDir tells the manager where session files are kept.
func (m *Manager) SetDataDir(dir string) {
	m.mu.Lock()
	m.dataDir = dir
	m.mu.Unlock()
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
	close(m.monitorStop)
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

			MonitorOn:       ep.cfg.MonitorEnabled(),
			MonitorInterval: ep.cfg.MonitorIntervalSeconds(),
			Alive:           ep.aliveState,
			AliveErr:        ep.aliveErr,
		}
		if !ep.aliveAt.IsZero() {
			v.AliveAt = ep.aliveAt.Unix()
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
	case model.AuthModeSSO:
		// Single sign-on keeps no password here: the browser login saved
		// the session, and the connector resumes it. When that session is
		// gone the connector says so, which is more useful than a
		// credential error.
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
	// A fresh login starts the validity report from scratch.
	cur.aliveFails = 0
	cur.aliveRetryAt = time.Time{}
	cur.retryStep = 0
	cur.aliveAt = time.Time{}
	cur.aliveState = ""
	cur.aliveErr = ""
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
	// Keep the session file current: it is what lets the next login resume
	// without a new QR code, and a stale copy would force one.
	m.persistSession(id)
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

// SaveSessionJSON stores a session obtained outside this process, such as the
// cookies a browser holds after an interactive single sign-on.
func (m *Manager) SaveSessionJSON(id string, data []byte) error {
	m.mu.RLock()
	dir := m.dataDir
	m.mu.RUnlock()
	if dir == "" {
		return errors.New("数据目录还没有就绪")
	}
	if err := writeClientData(dir, id, data); err != nil {
		return err
	}
	m.mu.Lock()
	if ep := m.points[id]; ep != nil {
		ep.aliveFails = 0
		ep.aliveRetryAt = time.Time{}
		ep.retryStep = 0
	}
	m.mu.Unlock()
	return nil
}

// Logout forgets the saved authentication of a point: the next login starts
// from a fresh QR code. Disconnect alone keeps it, so the next login resumes
// the existing session instead.
func (m *Manager) Logout(id string) {
	m.Disconnect(id)
	m.mu.RLock()
	dir := m.dataDir
	var name string
	if ep := m.points[id]; ep != nil {
		name = ep.cfg.Name
	}
	m.mu.RUnlock()
	if dir == "" {
		return
	}
	base := filepath.Join(dir, "atrust", id)
	removed := false
	for _, path := range []string{base + ".json", base + ".resource.json"} {
		if err := os.Remove(path); err == nil {
			removed = true
		}
	}
	if removed {
		m.logf("[%s] 已退出登录，清除保存的认证信息；下次登录需要重新扫码", name)
	} else {
		m.logf("[%s] 已退出登录（没有可清除的认证信息）", name)
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
	m.PersistSessions(m.dataDir)
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
	// A port another program holds must not disable the aggregate: walk to
	// the next free one and report where it ended up.
	var p *proxy.Server
	var lastErr error
	chosen := ""
	for i := 0; i <= 20; i++ {
		port := settings.AggregatePort + i
		addr := net.JoinHostPort(settings.ListenHost, fmt.Sprint(port))
		cand := proxy.New(proxy.Options{
			Addr: addr,
			Dial: m.Dial,
			Logf: func(format string, args ...any) {
				m.logf("[统一入口] "+format, args...)
			},
		})
		if err := cand.Start(); err != nil {
			lastErr = err
			continue
		}
		p = cand
		chosen = addr
		break
	}
	if p == nil {
		m.mu.Lock()
		m.aggregateErr = lastErr.Error()
		m.mu.Unlock()
		m.logf("统一入口监听失败：%v（端口可能被旧实例或别的程序占用，可在设置里换端口）", lastErr)
		m.changed()
		return
	}
	addr := chosen
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		_ = p.Close()
		return
	}
	m.aggregate = p
	m.mu.Unlock()
	if addr != net.JoinHostPort(settings.ListenHost, fmt.Sprint(settings.AggregatePort)) {
		m.logf("统一入口原端口被占用，改用 %s", addr)
	}
	m.logf("统一入口在 %s 监听，分流模式：%s", addr, settings.Routing.Label())
	m.changed()
}

// candidate is one online access point the aggregate proxy may use.
type candidate struct {
	id   string
	name string
	sess Session
	apps []App
	// served means the global TUN carries this point, so a connection goes
	// through the system route instead of a session.
	served bool
}

func (m *Manager) online() []candidate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]candidate, 0, len(m.order))
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil || ep.state != StateOnline || !ep.cfg.InPool {
			continue
		}
		if ep.sess == nil && !ep.tunServed {
			continue
		}
		out = append(out, candidate{
			id: id, name: ep.cfg.Name, sess: ep.sess,
			apps: ep.info.Apps, served: ep.tunServed,
		})
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
		dial := func(dctx context.Context, dnetwork, daddr string) (net.Conn, error) {
			return safeDial(dctx, c.sess, dnetwork, daddr)
		}
		if c.served {
			dial = directDial
		}
		conn, err := dial(ctx, network, addr)
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

// monitorLoop asks the portal, per access point and on its own schedule,
// whether the login is still the active one. Another client signing in with the
// same account takes the session over, and the tunnel keeps looking healthy.
func (m *Manager) monitorLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.monitorStop:
			return
		case <-ticker.C:
			m.checkSessions()
		}
	}
}

// checkSessions probes every online point whose interval has elapsed.
func (m *Manager) checkSessions() {
	type job struct {
		id   string
		name string
		sess Session
	}
	var jobs []job
	now := time.Now()
	m.mu.RLock()
	if !m.closed {
		for _, id := range m.order {
			ep := m.points[id]
			if ep == nil || ep.state != StateOnline {
				continue
			}
			if !ep.cfg.MonitorEnabled() {
				continue
			}
			// 单点登录的会话由浏览器产生，服务器的在线检查会把它当作
			// 「另一个客户端接管」而作废，隧道随即变成 invalid SID。
			// 这类接入点不做会话探测。
			if model.AuthMode(ep.cfg.AuthMode) == model.AuthModeSSO {
				continue
			}
			if ep.sess != nil {
				if _, ok := ep.sess.(AliveProber); !ok {
					continue
				}
			} else if !ep.tunServed {
				continue
			}
			if !ep.aliveRetryAt.IsZero() && now.Before(ep.aliveRetryAt) {
				continue
			}
			if ep.aliveRetryAt.IsZero() && !ep.aliveAt.IsZero() &&
				now.Sub(ep.aliveAt) < time.Duration(ep.cfg.MonitorIntervalSeconds())*time.Second {
				continue
			}
			jobs = append(jobs, job{id: id, name: ep.cfg.Name, sess: ep.sess})
		}
	}
	m.mu.RUnlock()

	for _, j := range jobs {
		go m.checkSession(j.id, j.name, j.sess)
	}
}

// checkSession runs one probe and acts on it. A network failure is only
// recorded: two real "session is not yours anymore" answers are needed before
// the point is taken down, so a flaky link cannot drop a working tunnel.
func (m *Manager) checkSession(id, name string, sess Session) {
	// 单点登录的会话一旦被服务器的在线检查认作另一个客户端，隧道就废了。
	// 这里统一拦住，手动「立即检测」也不会绕过。
	m.mu.RLock()
	if ep := m.points[id]; ep != nil && model.AuthMode(ep.cfg.AuthMode) == model.AuthModeSSO {
		m.mu.RUnlock()
		return
	}
	m.mu.RUnlock()

	var status AliveStatus
	var err error
	if sess == nil {
		// The tunnel belongs to the TUN helper, so probe the saved session
		// directly: the GUI has no client object of its own for this point.
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		status, err = m.probeSavedSession(ctx, id)
		cancel()
	} else {
		prober, ok := sess.(AliveProber)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		status, err = prober.CheckAlive(ctx)
		cancel()
	}

	m.mu.Lock()
	ep := m.points[id]
	if ep == nil || ep.state != StateOnline || (sess != nil && ep.sess != sess) {
		m.mu.Unlock()
		return
	}
	ep.aliveAt = time.Now()
	switch {
	case err != nil:
		ep.aliveState = "无法确认"
		ep.aliveErr = err.Error()
		ep.aliveRetryAt = time.Time{}
		m.mu.Unlock()
		m.logf("[%s] 会话检测暂时无法完成：%v", name, err)
		m.changed()
	case status.Valid:
		ep.aliveState = "有效"
		ep.aliveErr = ""
		ep.aliveFails = 0
		ep.aliveRetryAt = time.Time{}
		ep.retryStep = 0
		m.mu.Unlock()
		// A confirmed-good session is the best thing to keep on disk: it is
		// what a later login resumes instead of asking for a new QR code.
		m.persistSession(id)
		m.changed()
	default:
		// A session that came from a browser is not necessarily valid for the
		// web "onlineInfo" endpoint, while the tunnel built from it works. Such
		// a point is reported as unconfirmed and never torn down on this
		// answer; only a real login can replace it, and that needs the browser.
		if model.AuthMode(ep.cfg.AuthMode) == model.AuthModeSSO {
			ep.aliveState = "无法确认"
			ep.aliveErr = fmt.Sprintf("服务器未通过在线检查（code=%d），隧道不受影响", status.Code)
			ep.aliveFails = 0
			ep.aliveRetryAt = time.Time{}
			m.mu.Unlock()
			m.changed()
			return
		}
		ep.aliveFails++
		ep.aliveState = "已失效"
		reason := fmt.Sprintf("服务器判定会话已不可用（code=%d %s）", status.Code, status.Message)
		ep.aliveErr = reason
		final := ep.aliveFails >= 2
		if !final {
			// Recheck soon instead of waiting a whole interval: the server may
			// have answered mid-handover, and a false alarm must not linger.
			ep.aliveRetryAt = time.Now().Add(10 * time.Second)
		} else {
			ep.aliveRetryAt = time.Time{}
		}
		// 单点登录的重连需要用户在浏览器里操作，自动重连只会莫名弹出窗口。
		auto := m.settings.AutoReconnect && !m.closed &&
			model.AuthMode(ep.cfg.AuthMode) != model.AuthModeSSO
		m.mu.Unlock()
		m.logf("[%s] %s（第 %d 次）", name, reason, ep.aliveFails)
		if final {
			msg := "会话已被其它客户端顶掉：" + reason
			if auto {
				msg += "（稍后自动重试登录）"
			}
			m.markInvalid(id, msg, auto)
		} else {
			m.changed()
		}
	}
}

// SessionDataProvider is a Session that can hand out its cookies, so the TUN
// helper can resume the very same login.
type SessionDataProvider interface {
	ClientData() ([]byte, error)
}

// probeSavedSession asks the portal about a login while the TUN helper owns the
// only tunnel, using the session file the helper resumes.
func (m *Manager) probeSavedSession(ctx context.Context, id string) (AliveStatus, error) {
	m.mu.RLock()
	ep := m.points[id]
	dir := m.dataDir
	var server string
	var port int
	if ep != nil {
		server, port = ep.cfg.Server, ep.cfg.Port
	}
	m.mu.RUnlock()
	if ep == nil {
		return AliveStatus{}, errors.New("接入点不存在")
	}
	data, err := os.ReadFile(filepath.Join(dir, "atrust", id+".json"))
	if err != nil {
		return AliveStatus{}, fmt.Errorf("读取会话文件：%w", err)
	}
	online, err := atrustclient.CheckSavedOnline(server, port, data)
	res := AliveStatus{
		Username: online.Username,
		Code:     online.Code,
		Message:  online.Message,
		Valid:    err == nil && online.Code == 0,
	}
	return res, err
}

// persistSession writes one point's live cookies back to disk without the
// log noise of the batch version.
func (m *Manager) persistSession(id string) {
	m.mu.RLock()
	ep := m.points[id]
	dir := m.dataDir
	var sess Session
	var name string
	if ep != nil {
		sess, name = ep.sess, ep.cfg.Name
	}
	m.mu.RUnlock()
	if sess == nil || dir == "" {
		return
	}
	provider, ok := sess.(SessionDataProvider)
	if !ok {
		return
	}
	data, err := provider.ClientData()
	if err != nil {
		return
	}
	if err := writeClientData(dir, id, data); err != nil {
		m.logf("[%s] 无法写入会话文件：%v", name, err)
	}
}

// SetTunServed hands the tunnel of the given points over to the global TUN
// helper. The GUI closes its own session for them: aTrust keeps one tunnel per
// session, and with two of them the server keeps dropping one, which makes
// every request stall and eventually everything stop working.
func (m *Manager) SetTunServed(ids []string) {
	served := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id != "" {
			served[id] = true
		}
	}
	type handover struct {
		id     string
		name   string
		proxy  *proxy.Server
		sess   Session
		direct bool
	}
	var work []handover
	var reconnect []string

	m.mu.Lock()
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil {
			continue
		}
		want := served[id] && ep.state == StateOnline
		switch {
		case want && !ep.tunServed && ep.sess != nil:
			work = append(work, handover{
				id: id, name: ep.cfg.Name, proxy: ep.proxy,
				sess: ep.sess, direct: true,
			})
			ep.sess = nil
			ep.tunServed = true
			ep.aliveState = "由 TUN 接管"
			ep.aliveErr = ""
		case !want && ep.tunServed:
			// TUN no longer carries it: log in again so the point gets its
			// own tunnel back (a fresh proxy is created with that session).
			ep.tunServed = false
			ep.aliveState = ""
			if ep.state == StateOnline {
				reconnect = append(reconnect, id)
			}
		}
	}
	m.mu.Unlock()

	for _, h := range work {
		if h.proxy != nil {
			h.proxy.SetDial(directDial)
		}
		if h.sess != nil {
			_ = h.sess.Close()
		}
		m.logf("[%s] 已把隧道交给全局 TUN，应用侧改为系统路由", h.name)
	}
	for _, id := range reconnect {
		m.Connect(id)
	}
	if len(work) > 0 || len(reconnect) > 0 {
		m.changed()
	}
}

// directDial lets the operating system route the connection, which under a
// running TUN means into the tunnel.
func directDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 20 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// PersistSessions rewrites every online point's session file with the live
// cookies. The helper then resumes that session instead of logging in again,
// which would make the server drop the GUI's tunnel.
func (m *Manager) PersistSessions(dir string) {
	if dir == "" {
		return
	}
	type item struct {
		id   string
		name string
		sess Session
	}
	var items []item
	m.mu.RLock()
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil || ep.state != StateOnline || ep.sess == nil {
			continue
		}
		if _, ok := ep.sess.(SessionDataProvider); !ok {
			continue
		}
		items = append(items, item{id: id, name: ep.cfg.Name, sess: ep.sess})
	}
	m.mu.RUnlock()

	for _, it := range items {
		provider := it.sess.(SessionDataProvider)
		data, err := provider.ClientData()
		if err != nil {
			m.logf("[%s] 无法读取当前会话：%v", it.name, err)
			continue
		}
		if err := writeClientData(dir, it.id, data); err != nil {
			m.logf("[%s] 无法写入会话文件：%v", it.name, err)
			continue
		}
		m.logf("[%s] 已刷新会话文件，TUN 复用这次登录", it.name)
	}
}

// CheckNow runs one validity probe for a point right away, ignoring its
// schedule, so the user can test the setting.
func (m *Manager) CheckNow(id string) bool {
	m.mu.RLock()
	ep := m.points[id]
	if ep == nil || ep.state != StateOnline || (ep.sess == nil && !ep.tunServed) {
		m.mu.RUnlock()
		return false
	}
	sess, name := ep.sess, ep.cfg.Name
	m.mu.RUnlock()
	go m.checkSession(id, name, sess)
	return true
}

// markInvalid tears a session down and keeps the reason visible, instead of
// letting the point look merely offline.
func (m *Manager) markInvalid(id, msg string, autoReconnect bool) {
	var closes []closeLater
	m.mu.Lock()
	ep := m.points[id]
	if ep == nil {
		m.mu.Unlock()
		return
	}
	name := ep.cfg.Name
	m.stopEndpointLocked(id, &closes)
	ep.state = StateError
	ep.errMsg = msg
	ep.aliveState = "已失效"
	m.mu.Unlock()

	for _, c := range closes {
		if c.proxy != nil {
			_ = c.proxy.Close()
		}
		if c.sess != nil {
			_ = c.sess.Close()
		}
	}
	m.logf("[%s] %s", name, msg)
	m.changed()
	if autoReconnect {
		m.retryLogin(id)
	}
}

// loginRetryDelays is the backoff between automatic logins after the session
// was taken over. Five attempts, then it stops and waits for the user.
var loginRetryDelays = []time.Duration{
	15 * time.Second, 30 * time.Second, time.Minute,
	2 * time.Minute, 5 * time.Minute,
}

// retryLogin logs in again after a takeover, backing off so a failing server
// is not hammered.
func (m *Manager) retryLogin(id string) {
	m.mu.Lock()
	ep := m.points[id]
	if ep == nil || m.closed {
		m.mu.Unlock()
		return
	}
	step := ep.retryStep
	ep.retryStep++
	name := ep.cfg.Name
	m.mu.Unlock()
	if step >= len(loginRetryDelays) {
		m.logf("[%s] 已连续重试 %d 次仍未恢复，停止自动重连", name, len(loginRetryDelays))
		return
	}
	delay := loginRetryDelays[step]
	m.logf("[%s] 会话失效，%s 后自动重新登录（第 %d/%d 次）",
		name, delay.Round(time.Second), step+1, len(loginRetryDelays))
	m.reconnectAfter(id, delay)
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

// AliveStatus is what a session reports about its login still being valid on
// the server side.
type AliveStatus struct {
	Valid    bool
	Username string
	Code     int
	Message  string
}

// AliveProber is a Session that can ask the portal whether its login is still
// the active one, which a tunnel probe cannot tell.
type AliveProber interface {
	CheckAlive(ctx context.Context) (AliveStatus, error)
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
	served := false
	if online {
		sess = ep.sess
		served = ep.tunServed
	}
	m.mu.RUnlock()
	if !online || (sess == nil && !served) {
		return 0, errors.New("接入点未在线")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	// A point carried by the global TUN has no session: dial through the
	// system route, exactly like a browser does.
	dial := func(dctx context.Context, dnetwork, daddr string) (net.Conn, error) {
		return sess.Dial(dctx, dnetwork, daddr)
	}
	if served {
		dial = directDial
	}
	conn, err := dial(ctx, network, addr)
	if err != nil {
		return time.Since(start), err
	}
	_ = conn.Close()
	return time.Since(start), nil
}
