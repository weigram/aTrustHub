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
// and the fix is a fresh session.
type tunKeepAlive struct {
	mu    sync.Mutex
	fails map[string]int
	last  time.Time
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
// enough that the session should be re-created.
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

func (k *tunKeepAlive) reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.fails = map[string]int{}
	k.last = time.Time{}
}

// keepAliveTarget picks one address to dial for a point: a host that is a real
// IP with a port, because that is what the tunnel forwards.
func (a *app) keepAliveTarget(id string) string {
	for _, entry := range a.allApps() {
		if entry.PointID != id {
			continue
		}
		for _, addr := range entry.App.Addresses {
			host := strings.TrimSpace(addr.Host)
			if net.ParseIP(host) == nil || strings.Contains(host, "/") {
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

// checkTunnels probes every tunnel the helper owns and re-creates the session
// of one that keeps failing.
func (a *app) checkTunnels() {
	if !a.tunOn || a.tunPoints == "" {
		return
	}
	if !a.keepAlive.shouldRun(time.Now()) {
		return
	}
	for _, id := range splitIDs(a.tunPoints) {
		target := a.keepAliveTarget(id)
		if target == "" {
			continue
		}
		go func(id, target string) {
			conn, err := net.DialTimeout("tcp", target, 4*time.Second)
			if err == nil {
				_ = conn.Close()
				a.keepAlive.result(id, true)
				return
			}
			if !a.keepAlive.result(id, false) {
				return
			}
			// 会话在服务器侧已经废了，重登（复用已保存的会话）并让
			// helper 换成新的会话文件。
			a.tunLogf("隧道探测连续失败（%s），重新建立 %s 的会话", target, id)
			a.mgr.Reconnect(id)
		}(id, target)
	}
}
