package main

import (
	"sort"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// multitunPath is the bundled multi-point TUN helper.
func multitunPath() string {
	name := "zju-connect-multitun" + helperSuffix
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join("resources", name)
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// startGlobalTUN launches the bundled ZJU-Connect TUN engine as root, using
// the session already saved by the GUI (cookies + resource data), so no
// second login is needed. It creates a utun, adds routes and hijacks DNS.
// tunLogf writes a diagnostic line about the TUN helper to the app log.
func (a *app) tunLogf(format string, args ...any) {
	if a.bus != nil {
		a.bus.Add("app", fmt.Sprintf(format, args...))
	}
}

// tunPointConfig mirrors cmd/multitun's per-point configuration.
type tunPointConfig struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
	SID        string `json:"sid"`
	DeviceID   string `json:"deviceID"`
	ClientData string `json:"clientData"`
	Resource   string `json:"resource"`
	FakeCIDR   string `json:"fakeCIDR"`
}

type tunConfigFile struct {
	Points  []tunPointConfig `json:"points"`
	DNSBind string           `json:"dnsBind"`
}

// savedClient is what the GUI saved at login and the helper resumes from.
type savedClient struct {
	Cookies  []struct{ Name, Value string } `json:"cookies"`
	DeviceID string                         `json:"device_id"`
}

func (c savedClient) sid() string {
	for _, ck := range c.Cookies {
		if ck.Name == "sid" {
			return ck.Value
		}
	}
	return ""
}

// tunFakeRanges are the fake-IP blocks each access point gets in turn.
var tunFakeRanges = []string{
	"198.18.0.0/17", "198.18.128.0/17",
	"198.19.0.0/17", "198.19.128.0/17",
	"198.20.0.0/17", "198.20.128.0/17",
	"198.21.0.0/17", "198.21.128.0/17",
}

// startGlobalTUN runs one native aTrust TUN stack per online access point, so
// every point carries exactly its own resources, and internal names are
// mapped back to domains inside each stack (no proxy hop).
// ensureHelperSudo makes running helper need no password, once. It installs a
// sudoers rule for this exact binary; if that is impossible the caller falls
// back to the system authorization prompt.

// startGlobalTUN runs one native aTrust TUN stack per online access point.
func (a *app) startGlobalTUN(id string) {
	a.tunLogf("startGlobalTUN: 进入 id=%s", id)
	succeeded := false
	defer func() {
		if !succeeded && a.win != nil {
			a.win.Update(func() { a.tunPending = false })
		}
	}()
	if online, _, _ := a.mgr.Counts(); online == 0 {
		a.toast = "没有在线接入点，先登录再开 TUN"
		a.tunLogf("startGlobalTUN: 无在线接入点")
		return
	}
	helper := multitunPath()
	if _, err := os.Stat(helper); err != nil {
		a.toast = "找不到 TUN 组件：" + helper
		a.tunLogf("startGlobalTUN: 找不到 helper %s", helper)
		return
	}
	_ = os.Chmod(helper, 0o755)

	cfg := tunConfigFile{DNSBind: "127.0.0.1:53"}
	rangeIdx := 0
	for _, view := range a.mgr.Views() {
		if view.State != vpn.StateOnline {
			continue
		}
		point := a.cfg.Find(view.ID)
		if point == nil {
			continue
		}
		clientPath := filepath.Join(a.dir, "atrust", view.ID+".json")
		resourcePath := filepath.Join(a.dir, "atrust", view.ID+".resource.json")
		raw, err := os.ReadFile(clientPath)
		if err != nil {
			a.tunLogf("startGlobalTUN: %s 读取会话失败：%v", point.Name, err)
			continue
		}
		var cd savedClient
		if err := json.Unmarshal(raw, &cd); err != nil || cd.sid() == "" || cd.DeviceID == "" {
			a.tunLogf("startGlobalTUN: %s 会话不完整，请重新登录", point.Name)
			continue
		}
		if _, err := os.Stat(resourcePath); err != nil {
			a.tunLogf("startGlobalTUN: %s 缺少资源文件", point.Name)
			continue
		}
		fake := ""
		if rangeIdx < len(tunFakeRanges) {
			fake = tunFakeRanges[rangeIdx]
		}
		rangeIdx++
		cfg.Points = append(cfg.Points, tunPointConfig{
			Name: point.Name, Server: point.Server, Port: point.Port,
			SID: cd.sid(), DeviceID: cd.DeviceID,
			ClientData: clientPath, Resource: resourcePath, FakeCIDR: fake,
		})
	}
	if len(cfg.Points) == 0 {
		a.toast = "没有可用的登录会话，请重新登录一次"
		a.tunLogf("startGlobalTUN: 无可恢复会话")
		return
	}
	cfgPath := filepath.Join(a.dir, "tun-config.json")
	rawCfg, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, rawCfg, 0o600); err != nil {
		a.toast = "写 TUN 配置失败：" + err.Error()
		return
	}
	a.tunLogf("startGlobalTUN: %d 个接入点，配置 %s", len(cfg.Points), cfgPath)

	if a.sysProxyOn {
		_ = applySystemProxy("127.0.0.1:0", false)
		a.sysProxyOn = false
	}
	logPath := filepath.Join(a.dir, "tun.log")
	pidPath := filepath.Join(a.dir, "tun.pid")
	stopPath := filepath.Join(a.dir, "tun.stop")
	guiPath := filepath.Join(a.dir, "gui.alive")
	launchPath := filepath.Join(a.dir, "tun-launch.log")
	_ = os.Remove(pidPath)
	_ = os.Remove(stopPath)
	_ = os.Remove(a.accessLogPath())
	_ = os.WriteFile(guiPath, []byte("1"), 0o644)
	a.startGUIHeartbeat(guiPath)

	// Make later openings password-free; the first one may still prompt.
	args := []string{
		"-config", cfgPath,
		"-log-file", logPath,
		"-access-log", a.accessLogPath(),
		"-pid-file", pidPath,
		"-stop-file", stopPath,
		"-gui-file", guiPath,
	}
	privileged := true
	if err := a.ensureHelperPrivilege(helper, args); err != nil {
		privileged = false
		a.tunLogf("startGlobalTUN: 免密启动不可用，将回退为每次授权：%v", err)
	}

	a.win.Update(func() { a.toast = "正在开启全局 TUN…" })
	startErr := startHelper(helper, args, launchPath)
	if startErr != nil && !privileged {
		startErr = startHelperElevated(helper, args, launchPath)
	}
	if startErr != nil {
		a.toast = "开启全局 TUN 失败：" + startErr.Error()
		a.tunLogf("startGlobalTUN: 启动失败: %v", startErr)
		return
	}

	pid := 0
	for i := 0; i < 150; i++ {
		time.Sleep(200 * time.Millisecond)
		if b, err := os.ReadFile(pidPath); err == nil {
			if v, _ := strconv.Atoi(strings.TrimSpace(string(b))); v > 0 {
				pid = v
				break
			}
		}
	}
	alive := pid > 0 && pidFileFresh(pidPath, 8*time.Second)
	a.tunLogf("startGlobalTUN: pid=%d alive=%v", pid, alive)
	if !alive {
		tail := lastLines(logPath, 12)
		if extra := lastLines(launchPath, 3); extra != "" && !strings.Contains(tail, "started") {
			tail = extra + " ｜ " + tail
		}
		a.win.Update(func() {
			a.tunOn = false
			a.tunPID = 0
			a.tunPending = false
			a.toast = "全局 TUN 启动失败：" + tail
		})
		return
	}
	a.win.Update(func() {
		a.tunOn = true
		a.tunID = id
		a.tunPID = pid
		a.tunWanted = true
		a.tunPending = false
		a.tunPoints = a.onlineSnapshot()
	})
	succeeded = true
	a.persistTunState(true, id)
}

// onlineSnapshot is the set of access points the TUN helper was built for. It
// changes whenever a point logs in or out, which is the trigger for a rebuild.
func (a *app) onlineSnapshot() string {
	ids := make([]string, 0, 4)
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			ids = append(ids, v.ID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// maybeRefreshTUN rebuilds the TUN helper when the set of online points no
// longer matches the one it was started with, so a point logged in after TUN
// was switched on also gets its subnets routed. Rebuilds are debounced: a
// three-point login storm must not restart the tunnel three times.
func (a *app) maybeRefreshTUN() {
	var on, pending, refreshing bool
	var snap string
	a.win.Update(func() {
		on, pending, refreshing, snap = a.tunOn, a.tunPending, a.tunRefreshing, a.tunPoints
	})
	if !on || pending || refreshing {
		return
	}
	if a.onlineSnapshot() == snap {
		return
	}
	a.win.Update(func() { a.tunRefreshing = true })
	go func() {
		defer a.win.Update(func() { a.tunRefreshing = false })
		time.Sleep(3 * time.Second)
		var stillOn, stillPending bool
		a.win.Update(func() { stillOn, stillPending = a.tunOn, a.tunPending })
		if !stillOn || stillPending {
			return
		}
		if a.onlineSnapshot() == a.tunPoints {
			return
		}
		a.tunLogf("TUN 刷新：在线接入点变化（%s → %s），重建隧道", a.tunPoints, a.onlineSnapshot())
		a.win.Update(func() {
			a.tunPending = true
			a.tunOn = false
			a.tunPID = 0
		})
		_ = a.shutdownHelper(3 * time.Second)
		a.startGlobalTUN(a.tunID)
	}()
}

// pidFileFresh reports whether the helper wrote its pid file recently. The
// helper refreshes it every couple of seconds, which works the same on every
// platform, unlike signalling a process owned by another user.
func pidFileFresh(path string, maxAge time.Duration) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(st.ModTime()) < maxAge
}

func (a *app) persistTunState(on bool, id string) {
	_, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.TunEnabled = on
		if on {
			cfg.Settings.TunPointID = id
		}
		return nil
	})
	if err == nil {
		a.cfg = a.store.Config()
	}
}

// lastLines returns the tail of a log file for the failure toast.
func lastLines(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "（读取日志失败：" + err.Error() + "）"
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

func (a *app) stopGlobalTUN() {
	stopped := a.shutdownHelper(10 * time.Second)
	a.win.Update(func() {
		a.tunOn = false
		a.tunPID = 0
		a.tunPending = false
		a.tunWanted = false
		a.tunPoints = ""
		a.tunResumeTried = true
		if stopped {
			a.toast = "全局 TUN 已关闭，DNS 已恢复"
		} else {
			a.toast = "已请求关闭 TUN，若仍生效请稍候"
		}
	})
	a.persistTunState(false, "")
}

// startGUIHeartbeat keeps the helper's "the app is alive" file fresh, so the
// helper exits on its own if this process dies without cleaning up.
func (a *app) startGUIHeartbeat(path string) {
	a.heartbeatOnce.Do(func() {
		go func() {
			for {
				now := time.Now()
				_ = os.Chtimes(path, now, now)
				time.Sleep(2 * time.Second)
			}
		}()
	})
}

// shutdownHelper asks the helper to stop, then forces it if it lingers. It
// reports whether the helper is gone.
func (a *app) shutdownHelper(wait time.Duration) bool {
	stopPath := filepath.Join(a.dir, "tun.stop")
	pidPath := filepath.Join(a.dir, "tun.pid")
	_ = os.WriteFile(stopPath, []byte("stop\n"), 0o644)
	pid := a.tunPID
	if pid <= 0 {
		if b, err := os.ReadFile(pidPath); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		if pid > 0 && !helperAlive(pid) {
			_ = os.Remove(stopPath)
			_ = os.Remove(pidPath)
			return true
		}
		if pid <= 0 {
			if _, err := os.Stat(pidPath); err != nil {
				_ = os.Remove(stopPath)
				return true
			}
		}
	}
	// The helper did not leave on its own: stop it, so no orphan keeps the
	// utun, routes and DNS hijacked.
	if pid > 0 && helperAlive(pid) {
		a.tunLogf("shutdownHelper: 强制结束 helper pid=%d", pid)
		if err := terminateHelper(pid); err != nil {
			a.tunLogf("shutdownHelper: 强制结束失败：%v", err)
		}
		for i := 0; i < 25; i++ {
			time.Sleep(200 * time.Millisecond)
			if !helperAlive(pid) {
				_ = os.Remove(stopPath)
				_ = os.Remove(pidPath)
				return true
			}
		}
		return false
	}
	_ = os.Remove(stopPath)
	_ = os.Remove(pidPath)
	return true
}

// stopTUNQuiet kills the helper and restores DNS without touching the UI,
// for shutdown.
func (a *app) stopTUNQuiet() {
	// Keep quitting responsive: ask the helper to leave, don't wait long.
	_ = a.shutdownHelper(2 * time.Second)
}
