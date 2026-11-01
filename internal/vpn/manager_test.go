package vpn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
)

type fakeSession struct {
	id      string
	info    SessionInfo
	dialErr error

	mu     sync.Mutex
	dials  []string
	done   chan struct{}
	close  sync.Once
	closed bool
}

func newFakeSession(id string) *fakeSession {
	return &fakeSession{id: id, info: SessionInfo{ClientIP: "10.0.0.1"}, done: make(chan struct{})}
}

func (f *fakeSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, addr)
	err := f.dialErr
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return nil, errors.New("closed")
	}
	if err != nil {
		return nil, err
	}
	a, b := net.Pipe()
	go func() {
		_, _ = io.WriteString(b, f.id)
		_ = b.Close()
	}()
	return a, nil
}

func (f *fakeSession) Info() SessionInfo { return f.info }

func (f *fakeSession) Close() error {
	f.close.Do(func() {
		f.mu.Lock()
		f.closed = true
		f.mu.Unlock()
		close(f.done)
	})
	return nil
}

type fakeConnector struct {
	mu       sync.Mutex
	block    chan struct{}
	started  chan string
	fail     map[string]error
	sessions map[string]*fakeSession
}

func (f *fakeConnector) Connect(ctx context.Context, p model.AccessPoint, creds Credentials) (Session, error) {
	if f.started != nil {
		f.started <- p.ID
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := f.fail[p.ID]; err != nil {
		return nil, err
	}
	s := newFakeSession(p.ID)
	f.mu.Lock()
	if f.sessions == nil {
		f.sessions = map[string]*fakeSession{}
	}
	f.sessions[p.ID] = s
	f.mu.Unlock()
	return s, nil
}

func (f *fakeConnector) session(id string) *fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions[id]
}

func testConfig(points ...model.AccessPoint) model.Config {
	s := model.DefaultSettings()
	s.AggregateEnabled = false
	s.HealthIntervalSec = 0
	cfg := model.Config{Version: model.CurrentVersion, Settings: s, Points: points}
	cfg.Normalize()
	for i := range cfg.Points {
		cfg.Points[i].SocksPort = 0
	}
	return cfg
}

func newTestManager(t *testing.T, c Connector, cfg model.Config) *Manager {
	t.Helper()
	bus := NewLogBus(100)
	m := NewManager(c, func(id string) (Credentials, error) {
		return Credentials{Login: "pw-for-test"}, nil
	}, bus, nil)
	t.Cleanup(m.Close)
	m.Apply(cfg)
	return m
}

func waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestConnectAllConcurrent(t *testing.T) {
	conn := &fakeConnector{
		block:   make(chan struct{}),
		started: make(chan string, 4),
	}
	cfg := testConfig(
		model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", AutoConnect: true, InPool: true},
		model.AccessPoint{ID: "b", Name: "B", Server: "b.example", Port: 443, Username: "u", AutoConnect: true, InPool: true},
	)
	m := newTestManager(t, conn.Connect, cfg)

	if n := m.ConnectAll(true); n != 2 {
		t.Fatalf("ConnectAll = %d", n)
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-conn.started:
			seen[id] = true
		case <-time.After(3 * time.Second):
			t.Fatal("only one login started")
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("started = %v", seen)
	}
	close(conn.block)
	waitFor(t, "both online", func() bool {
		online, _, _ := m.Counts()
		return online == 2
	})
	if _, _, total := m.Counts(); total != 2 {
		t.Errorf("total = %d", total)
	}
	m.DisconnectAll()
	waitFor(t, "both offline", func() bool {
		online, _, _ := m.Counts()
		return online == 0
	})
}

func TestLoginFailureIsReported(t *testing.T) {
	conn := &fakeConnector{fail: map[string]error{"a": errors.New("bad password")}}
	cfg := testConfig(model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true})
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "error state", func() bool {
		v, _ := m.View("a")
		return v.State == StateError && v.Error != ""
	})
}

func TestAggregateFailover(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(
		model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true},
		model.AccessPoint{ID: "b", Name: "B", Server: "b.example", Port: 443, Username: "u", InPool: true},
	)
	cfg.Settings.Routing = model.RoutingFailover
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	m.Connect("b")
	waitFor(t, "online", func() bool { online, _, _ := m.Counts(); return online == 2 })

	conn.session("a").mu.Lock()
	conn.session("a").dialErr = errors.New("tunnel down")
	conn.session("a").mu.Unlock()

	c, err := m.Dial(context.Background(), "tcp", "intranet.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "b" {
		t.Errorf("dial went through %q, want b", buf)
	}
	if got := len(conn.session("a").dials); got != 1 {
		t.Errorf("A tried %d times", got)
	}
	if got := len(conn.session("b").dials); got != 1 {
		t.Errorf("B tried %d times", got)
	}
}

func TestAggregateNoOnline(t *testing.T) {
	m := newTestManager(t, (&fakeConnector{}).Connect, testConfig())
	if _, err := m.Dial(context.Background(), "tcp", "x:1"); err == nil {
		t.Fatal("Dial succeeded with no online point")
	}
}

func TestMissingCredentials(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true})
	bus := NewLogBus(50)
	m := NewManager(conn.Connect, func(string) (Credentials, error) {
		return Credentials{}, ErrNoCredentials
	}, bus, nil)
	t.Cleanup(m.Close)
	m.Apply(cfg)
	m.Connect("a")
	waitFor(t, "missing credentials", func() bool {
		v, _ := m.View("a")
		return v.State == StateError
	})
	v, _ := m.View("a")
	if v.Error == "" {
		t.Error("no message about the missing credentials")
	}
}

func TestApplyRemovesPoint(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true})
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool { online, _, _ := m.Counts(); return online == 1 })

	m.Apply(testConfig())
	if len(m.Views()) != 0 {
		t.Error("removed point still shown")
	}
	if s := conn.session("a"); s != nil {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if !closed {
			t.Error("removed point was not disconnected")
		}
	}
}

func TestViewsOrder(t *testing.T) {
	cfg := testConfig(
		model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u"},
		model.AccessPoint{ID: "b", Name: "B", Server: "b.example", Port: 443, Username: "u"},
	)
	m := newTestManager(t, (&fakeConnector{}).Connect, cfg)
	views := m.Views()
	if len(views) != 2 || views[0].ID != "a" || views[1].ID != "b" {
		t.Errorf("views = %+v", views)
	}
}

func TestNodeSummary(t *testing.T) {
	v := View{BestNodes: map[string]string{"z": "1.1.1.1:443", "a": "2.2.2.2:443"}}
	lines := NodeSummary(v)
	if len(lines) != 2 || lines[0] != "a → 2.2.2.2:443" {
		t.Errorf("lines = %v", lines)
	}
}

var _ = fmt.Sprint

func TestLatencyModeSamplesEveryPoint(t *testing.T) {
	cfg := testConfig(
		model.AccessPoint{ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true},
		model.AccessPoint{ID: "b", Name: "B", Server: "b.example", Port: 443, Username: "u", InPool: true},
	)
	cfg.Settings.Routing = model.RoutingLatency
	m := newTestManager(t, (&fakeConnector{}).Connect, cfg)
	pool := m.online()
	if len(pool) != 0 {
		t.Fatal("points are online without a login")
	}
	m.mu.Lock()
	m.points["a"].state = StateOnline
	m.points["a"].sess = newFakeSession("a")
	m.points["b"].state = StateOnline
	m.points["b"].sess = newFakeSession("b")
	m.mu.Unlock()

	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		c, ok := m.pick(m.online(), model.RoutingLatency, map[string]bool{})
		if !ok {
			t.Fatal("no candidate")
		}
		seen[c.id] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("latency mode picked %v before any measurement", seen)
	}

	m.recordSuccess("a", 10*time.Millisecond)
	m.recordSuccess("b", 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		c, ok := m.pick(m.online(), model.RoutingLatency, map[string]bool{})
		if !ok || c.id != "a" {
			t.Fatalf("pick = %v, %v; want a", c.id, ok)
		}
	}
}
