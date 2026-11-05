package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tunKeepAlive notices a tunnel that died while the app still shows the access
// point as logged in. A TUN session can expire on the server side when nothing
// is flowing through it; without a probe the only symptom is "访问不了应用"，
// and the fix is a fresh tunnel, not a new login.
type tunKeepAlive struct {
	mu    sync.Mutex
	fails map[string]int
	last  time.Time
	// rebuilds records automatic TUN rebuilds, so a tunnel that keeps dying
	// cannot restart the helper forever.
	rebuilds []time.Time
}

func (k *tunKeepAlive) shouldRun(now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if now.Sub(k.last) < 90*time.Second {
		return false
	}
	k.last = now
	return true
}

// result records one probe. It returns true when the tunnel has failed often
// enough that it should be rebuilt.
func (k *tunKeepAlive) result(id string, ok bool) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fails == nil {
		k.fails = map[string]int{}
	}
	if ok {
		k.fails[id] = 0
		return false
	}
	k.fails[id]++
	if k.fails[id] >= 2 {
		k.fails[id] = 0
		return true
	}
	return false
}

// failsFor reports the consecutive failures recorded for a point.
func (k *tunKeepAlive) failsFor(id string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fails[id]
}

// mayRebuild allows a bounded number of automatic rebuilds in a window.
func (k *tunKeepAlive) mayRebuild(now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	cut := now.Add(-15 * time.Minute)
	kept := k.rebuilds[:0]
	for _, at := range k.rebuilds {
		if at.After(cut) {
			kept = append(kept, at)
		}
	}
	k.rebuilds = kept
	return len(kept) < 3
}

func (k *tunKeepAlive) noteRebuild(now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rebuilds = append(k.rebuilds, now)
}

func (k *tunKeepAlive) reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fails = map[string]int{}
	k.last = time.Time{}
}

// keepAliveTarget picks one address to dial for a point: a host that is a real
// IP with a port, because that is what the tunnel forwards and what the helper
// can probe by address.
func (a *app) keepAliveTarget(id string) string {
	for _, entry := range a.allApps() {
		if entry.PointID != id {
			continue
		}
		for _, addr := range entry.App.Addresses {
			// Only TCP-tunnel resources can be probed by dialing; L3-only
			// addresses would always look like a failure.
			proto := strings.ToLower(strings.TrimSpace(addr.Protocol))
			if proto != "" && proto != "tcp" && proto != "all" {
				continue
			}
			host := strings.TrimSpace(addr.Host)
			if net.ParseIP(host) == nil || strings.ContainsAny(host, "/-") {
				continue
			}
			port := strings.TrimSpace(addr.Port)
			if _, err := strconv.Atoi(port); err != nil {
				continue
			}
			return net.JoinHostPort(host, port)
		}
	}
	return ""
}

// checkTunnels probes every tunnel the helper owns. A local dial proves
// nothing under TUN (the local stack completes the handshake), so the helper
// dials through the aTrust session instead; only a real failure counts.
func (a *app) checkTunnels() {
	if !a.tunOn || a.tunPoints == "" {
		return
	}
	// 0 turns the health check off; honour it for TUN probes as well.
	if a.cfg.Settings.HealthIntervalSec <= 0 {
		return
	}
	if !a.keepAlive.shouldRun(time.Now()) {
		return
	}
	for _, id := range splitIDs(a.tunPoints) {
		target := a.keepAliveTarget(id)
		point := a.cfg.Find(id)
		if target == "" || point == nil {
			continue
		}
		go func(id, name, target string) {
			ok, _, errText, answered, skip := a.probeTunnel(name, target, 6*time.Second)
			if !answered {
				// An older helper cannot answer probes; do not fake a failure.
				a.tunLogf("隧道保活：helper 未应答探测 %s（%s）", target, name)
				return
			}
			if skip {
				// The address is carried by L3, not the TCP tunnel, so a dial
				// cannot test it. Leave the point to the next target instead
				// of reporting a failure.
				a.tunLogf("隧道保活：跳过 %s（%s）：%s", target, name, errText)
				return
			}
			if ok {
				a.keepAlive.result(id, true)
				a.mgr.SetTunnelState(id, "", "")
				return
			}
			if !a.keepAlive.result(id, false) {
				fails := a.keepAlive.failsFor(id)
				a.mgr.SetTunnelState(id, "degraded",
					"隧道保活探测失败（"+strconv.Itoa(fails)+"/2）："+errText)
				a.tunLogf("隧道保活探测失败（%s，%d/2）：%s", target, fails, errText)
				return
			}
			reason := "隧道保活连续失败（" + target + "）：" + errText
			if !a.keepAlive.mayRebuild(time.Now()) {
				reason = "隧道多次重建后仍然失效，请手动重新登录该接入点，或关闭再打开全局 TUN"
				a.mgr.SetTunnelState(id, "dead", reason)
				a.tunLogf("%s（%s）", reason, errText)
				return
			}
			a.keepAlive.noteRebuild(time.Now())
			a.mgr.SetTunnelState(id, "dead", reason)
			a.tunLogf("%s，重建全局 TUN", reason)
			a.rebuildTUNAfterTunnelFailure(id, reason)
		}(id, point.Name, target)
	}
}

// rebuildTUNAfterTunnelFailure restarts the helper from freshly saved sessions.
// The GUI first takes every point back from the helper, which logs each one in
// again by resuming its saved session — a valid login therefore produces a new
// tunnel without asking the user to sign in again.
func (a *app) rebuildTUNAfterTunnelFailure(id, reason string) {
	if a.win == nil {
		return
	}
	a.keepAlive.reset()
	go func() {
		a.tunSeq.Lock()
		defer a.tunSeq.Unlock()
		if !a.tunOn && !a.tunPending {
			return
		}
		a.tunLogf("重建 TUN：%s", reason)
		a.win.Update(func() {
			a.tunPending = true
			a.toast = "检测到隧道失效，正在重建全局 TUN…"
			a.tunMirror()
		})
		_ = a.shutdownHelper(8 * time.Second)
		// Hand the points back so their sessions are refreshed from disk and
		// the helper never starts from a stale SID.
		a.mgr.SetTunServed(nil)
		a.win.Update(func() {
			a.tunOn = false
			a.tunPID = 0
			a.tunPending = false
			a.tunPoints = ""
			a.tunWanted = true
			a.tunResumeAt = time.Time{}
			a.tunResumeFails = 0
			a.tunMirror()
		})
		a.persistTunState(true, id)
	}()
	a.invalidate()
}
