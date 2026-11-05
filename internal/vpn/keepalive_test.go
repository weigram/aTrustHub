package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
)

func tunnelApps() []App {
	return []App{{
		ID:   "app-1",
		Name: "内部数据库",
		Addresses: []AppAddress{
			{Protocol: "tcp", Host: "10.1.2.3", Port: "3306"},
		},
	}}
}

// probeNow clears the probe throttle so a test can run several rounds back to
// back.
func probeNow(m *Manager, id string) {
	m.mu.Lock()
	if ep := m.points[id]; ep != nil {
		ep.lastProbe = time.Time{}
	}
	m.mu.Unlock()
	m.probeAll(true)
}

func TestIdleProbeSkipsRecentlyUsedTunnel(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.mu.Unlock()

	// A tunnel that just carried traffic must not be probed.
	m.noteTraffic("a")
	m.probeAll(true)

	sess.mu.Lock()
	dials := len(sess.dials)
	sess.mu.Unlock()
	if dials != 0 {
		t.Fatalf("probe dialed a busy tunnel %d times", dials)
	}
	if v, _ := m.View("a"); v.TunnelState != "" {
		t.Errorf("tunnel state = %q, want empty", v.TunnelState)
	}
}

func TestIdleProbeMarksDeadTunnelAndSchedulesRebuild(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	sess.dialErr = errors.New("tunnel closed by server")

	// connect() stamps lastTraffic; clear it so the tunnel counts as idle.
	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.points["a"].lastTraffic = time.Time{}
	m.mu.Unlock()

	probeNow(m, "a")
	v, _ := m.View("a")
	if v.TunnelState != "degraded" || v.TunnelFails != 1 {
		t.Fatalf("after one failure: state=%q fails=%d, want degraded/1", v.TunnelState, v.TunnelFails)
	}
	if v.State != StateOnline {
		t.Fatalf("state = %v, want still online after first failure", v.State)
	}

	probeNow(m, "a")
	probeNow(m, "a")
	v, _ = m.View("a")
	if v.State != StateError || v.TunnelState != "dead" {
		t.Fatalf("after three failures: state=%v tunnel=%q, want error/dead", v.State, v.TunnelState)
	}
	if !strings.Contains(v.Error, "隧道已失效") {
		t.Errorf("error = %q, want it to say the tunnel died while the login stays valid", v.Error)
	}
	m.mu.Lock()
	step := m.points["a"].retryStep
	m.mu.Unlock()
	if step == 0 {
		t.Error("no automatic rebuild was scheduled")
	}
}

type unprobeableSession struct {
	*fakeSession
}

func (u unprobeableSession) Probe(context.Context) error { return errProbeUnavailable }

func TestUnprobeableTunnelIsNotAFailure(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	// No application address and no remote DNS: nothing to probe through.
	m.mu.Lock()
	m.points["a"].sess = unprobeableSession{m.points["a"].sess.(*fakeSession)}
	m.points["a"].lastTraffic = time.Time{}
	m.mu.Unlock()

	m.probeAll(true)
	v, _ := m.View("a")
	if v.TunnelState != "" || v.TunnelFails != 0 {
		t.Fatalf("tunnel state = %q fails = %d, want untouched", v.TunnelState, v.TunnelFails)
	}
	if v.State != StateOnline {
		t.Fatalf("state = %v, want online", v.State)
	}
}

func TestKeepAliveTargetSkipsDomainsAndRanges(t *testing.T) {
	apps := []App{{Addresses: []AppAddress{
		{Protocol: "tcp", Host: "db.internal.example", Port: "3306"},
		{Protocol: "tcp", Host: "10.0.0.1-10.0.0.9", Port: "443"},
		{Protocol: "tcp", Host: "10.1.2.3", Port: "3306"},
	}}}
	if got, want := keepAliveTarget(apps), "10.1.2.3:3306"; got != want {
		t.Fatalf("keepAliveTarget = %q, want %q", got, want)
	}
	if got := keepAliveTarget(nil); got != "" {
		t.Fatalf("keepAliveTarget(nil) = %q, want empty", got)
	}
}
