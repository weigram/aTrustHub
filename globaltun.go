package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// multitunPath is the bundled multi-point TUN helper. It is looked up in a
// few places, because the app works whether it runs from the .app bundle, from
// a development build directory, or from a copy the user moved elsewhere.
func multitunPath() (path, tried string) {
	name := "zju-connect-multitun" + helperSuffix
	var candidates []string
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	// Next to the executable: the bundle layout on macOS and the install
	// directory on Windows both keep it there.
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, name),
			filepath.Join(exeDir, "Resources", name),
			filepath.Join(exeDir, "..", "Resources", name),
		)
	}
	candidates = append(candidates,
		filepath.Join("resources", name),
		filepath.Join("resources", runtime.GOOS+"-"+runtime.GOARCH, name),
	)
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, ""
		}
	}
	return filepath.Join("resources", name), strings.Join(candidates, " ｜ ")
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
	// DisabledApps are application IDs kept out of this tunnel.
	DisabledApps []string `json:"disabledApps,omitempty"`
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
// splitIDs turns the comma-joined snapshot back into a list.
func splitIDs(snapshot string) []string {
	if snapshot == "" {
		return nil
	}
	return strings.Split(snapshot, ",")
}

// tunConfigFor builds the helper configuration from the online access points.
func (a *app) tunConfigFor() (tunConfigFile, error) {
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
			DisabledApps: point.DisabledApps,
		})
	}
	if len(cfg.Points) == 0 {
		return cfg, fmt.Errorf("没有可用的登录会话，请重新登录一次")
	}
	return cfg, nil
}

func (a *app) startGlobalTUN(id string) {
	if a.win == nil {
		a.tunLogf("startGlobalTUN: 主窗口还没创建，跳过 id=%s", id)
		return
	}
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
	helper, tried := multitunPath()
	if _, err := os.Stat(helper); err != nil {
		a.toast = "找不到 TUN 组件：" + helper
		a.tunLogf("startGlobalTUN: 找不到 helper，已尝试：%s", tried)
		return
	}
	_ = os.Chmod(helper, 0o755)

	// The helper resumes the GUI's login, so its session file must carry the
	// SID in use right now; a second login would drop this session.
	a.mgr.PersistSessions(a.dir)

	cfg, err := a.tunConfigFor()
	if err != nil {
		a.toast = err.Error()
		a.tunLogf("startGlobalTUN: %v", err)
		return
	}
	if len(cfg.Points) == 0 {
		a.toast = "没有可用的登录会话，请重新登录一次"
		a.tunLogf("startGlobalTUN: 无可恢复会话")
		return
	}
	if pidFileFresh(filepath.Join(a.dir, "tun.pid"), 10*time.Second) {
		a.tunLogf("startGlobalTUN: 检测到仍在运行的 TUN 组件，先停掉再启动")
		_ = a.shutdownHelper(3 * time.Second)
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
		"-reload-file", filepath.Join(a.dir, "tun.reload"),
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
	// 系统 DNS 现在指向 helper。如果它其实没在应答（例如端口被上一轮
	// 残留的 root 进程占着），整台机器就解析不了任何域名——先确认再宣告成功。
	skipCheck := os.Getenv("HUB_KEEP_TUN") == "1"
	if !skipCheck && !helperAnswersDNS(25*time.Second, a.dnsProbeName(id)) {
		a.tunLogf("startGlobalTUN: helper 未在 127.0.0.1:53 应答，撤销这次启动")
		_ = a.shutdownHelper(6 * time.Second)
		a.mgr.SetTunServed(nil)
		a.win.Update(func() {
			a.tunOn = false
			a.tunPID = 0
			a.tunPending = false
			a.tunWanted = false
			a.tunPoints = ""
			a.tunMirror()
			a.toast = "全局 TUN 启动失败：DNS 未能就绪（可能有残留的旧进程占用 53 端口）"
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
		a.tunMirror()
	})
	succeeded = true
	// The helper owns the tunnel now: the point's own proxy must dial through
	// the system, or the two tunnels would fight over one session. Read the
	// online set directly: a.tunPoints is written by the queued win.Update
	// above and may not be visible yet.
	served := make([]string, 0, len(cfg.Points))
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			served = append(served, v.ID)
		}
	}
	a.mgr.SetTunServed(served)
	a.tunLogf("TUN 已接管 %d 个接入点，应用侧代理改走系统路由", len(served))
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
// tunMirror copies the UI-owned TUN state into the atomics that background
// goroutines read.
func (a *app) tunMirror() {
	a.tunOnA.Store(a.tunOn)
	a.tunPendingA.Store(a.tunPending)
	a.tunPointsA.Store(a.tunPoints)
	a.tunIDA.Store(a.tunID)
}

func (a *app) maybeRefreshTUN() {
	if a.win == nil {
		return
	}
	snap, _ := a.tunPointsA.Load().(string)
	if !a.tunOnA.Load() || a.tunPendingA.Load() {
		return
	}
	now := a.onlineSnapshot()
	if now == snap {
		return
	}
	// One rebuild at a time: the ticker and every log line can land here at
	// the same moment, and two helpers on one machine fight over routes.
	if !a.tunGate.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.tunGate.Store(false)
		time.Sleep(3 * time.Second)
		if !a.tunOnA.Load() || a.tunPendingA.Load() {
			return
		}
		if a.onlineSnapshot() == a.tunPointsA.Load().(string) {
			return
		}
		prev, _ := a.tunPointsA.Load().(string)
		nowSnap := a.onlineSnapshot()
		a.tunLogf("TUN 刷新：在线接入点变化（%s → %s）", prev, nowSnap)
		a.tunSeq.Lock()
		added, err := a.extendTUN(prev, nowSnap)
		if err == nil && added {
			a.tunPointsA.Store(nowSnap)
			a.mgr.SetTunServed(splitIDs(nowSnap))
			go a.win.Update(func() {
				a.tunPoints = nowSnap
				a.tunPending = false
			})
			a.tunSeq.Unlock()
			return
		}
		// Points were removed, or extending failed: rebuild from scratch.
		a.tunLogf("TUN 刷新：改为整体重建（%v）", err)
		a.tunPendingA.Store(true)
		a.tunOnA.Store(false)
		go a.win.Update(func() {
			a.tunPending = true
			a.tunOn = false
			a.tunPID = 0
		})
		_ = a.shutdownHelper(3 * time.Second)
		a.startGlobalTUN(a.tunID)
		a.tunSeq.Unlock()
	}()
}

// extendTUN adds the newly online points to the running helper without
// touching the tunnels that already work: the helper re-reads the config when
// a reload file appears. It reports whether a reload was requested.
func (a *app) extendTUN(prev, now string) (bool, error) {
	a.mgr.PersistSessions(a.dir)
	if prev == "" {
		return false, fmt.Errorf("没有已建立的隧道")
	}
	if !pidFileFresh(filepath.Join(a.dir, "tun.pid"), 10*time.Second) {
		return false, fmt.Errorf("TUN 组件未在运行")
	}
	prevSet := strings.Split(prev, ",")
	known := map[string]bool{}
	for _, id := range prevSet {
		known[id] = true
	}
	_ = known
	// Every previously online point must still be online: a removal needs a
	// different tunnel set, which only a rebuild can provide.
	for _, id := range prevSet {
		found := false
		for _, cur := range strings.Split(now, ",") {
			if cur == id {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("有接入点离线")
		}
	}
	// The helper resumes the GUI's login, so its session file must carry the
	// SID in use right now; a second login would drop this session.
	a.mgr.PersistSessions(a.dir)

	cfg, err := a.tunConfigFor()
	if err != nil {
		return false, err
	}
	cfgPath := filepath.Join(a.dir, "tun-config.json")
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		return false, err
	}
	reload := filepath.Join(a.dir, "tun.reload")
	if err := os.WriteFile(reload, []byte("reload\n"), 0o644); err != nil {
		return false, err
	}
	a.tunLogf("TUN 增量：已请求 helper 加入新接入点，现有点保持不变")
	return true, nil
}

// startTUNSerialized and stopTUNSerialized keep manual switch flips from
// overlapping an automatic rebuild.
func (a *app) startTUNSerialized(id string) {
	a.tunSeq.Lock()
	defer a.tunSeq.Unlock()
	a.startGlobalTUN(id)
}

func (a *app) stopTUNSerialized() {
	a.tunSeq.Lock()
	defer a.tunSeq.Unlock()
	a.stopGlobalTUN()
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
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.TunEnabled = on
		if on {
			cfg.Settings.TunPointID = id
		}
		return nil
	}); err != nil {
		return
	}
	// Update 只改内存，落盘要显式 Save，否则重启后记不住开关位置。
	_ = a.saveConfig()
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
	// Back to the point's own tunnel.
	a.mgr.SetTunServed(nil)
	a.win.Update(func() {
		a.tunOn = false
		a.tunPID = 0
		a.tunPending = false
		a.tunWanted = false
		a.tunPoints = ""
		a.tunMirror()
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

// probeTunnel asks the running helper to open one connection through the
// tunnel. TUN completes the TCP handshake locally, so a plain dial reports
// success in a couple of milliseconds even when nothing is reachable; only the
// helper can tell the truth.
func (a *app) probeTunnel(pointName, addr string, wait time.Duration) (bool, int64, string, bool) {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	reqPath := filepath.Join(a.dir, "tun.probe")
	resPath := reqPath + ".result"
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	_ = os.Remove(resPath)
	if err := os.WriteFile(reqPath, []byte(id+"|"+pointName+"|"+addr), 0o600); err != nil {
		return false, 0, "", false
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(resPath)
		if err == nil && len(data) > 0 {
			var out struct {
				ID    string `json:"id"`
				OK    bool   `json:"ok"`
				MS    int64  `json:"ms"`
				Error string `json:"error"`
			}
			if json.Unmarshal(data, &out) == nil && out.ID == id {
				_ = os.Remove(resPath)
				return out.OK, out.MS, out.Error, true
			}
			time.Sleep(80 * time.Millisecond)
			continue
		}
		time.Sleep(80 * time.Millisecond)
	}
	return false, 0, "", false
}

// pickResumePoint chooses which access point the remembered TUN should use:
// the remembered one when it is online, otherwise the first online point.
func pickResumePoint(preferred string, views []vpn.View) string {
	for _, v := range views {
		if v.ID == preferred && v.State == vpn.StateOnline {
			return v.ID
		}
	}
	for _, v := range views {
		if v.State == vpn.StateOnline {
			return v.ID
		}
	}
	return ""
}

// helperAnswersDNS asks the helper's resolver about a name every machine
// knows, so a dead 127.0.0.1:53 is caught before the system is pointed at it.
func helperAnswersDNS(wait time.Duration, name string) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if dnsQueryAnswers(name) {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// dnsProbeName picks a name the helper must be able to answer: an internal
// domain of the point when there is one, otherwise the access point's host.
// "localhost" is useless here because the helper answers it from a builtin
// table even when its tunnel resolution is broken.
func (a *app) dnsProbeName(id string) string {
	for _, entry := range a.allApps() {
		if entry.PointID != id {
			continue
		}
		for _, addr := range entry.App.Addresses {
			if addr.Host != "" && net.ParseIP(addr.Host) == nil {
				return addr.Host
			}
		}
	}
	if p := a.cfg.Find(id); p != nil && p.Server != "" {
		return p.Server
	}
	return "www.baidu.com"
}

// dnsQueryAnswers sends one A query to 127.0.0.1:53 and waits for any answer.
func dnsQueryAnswers(name string) bool {
	conn, err := net.DialTimeout("udp", "127.0.0.1:53", time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := buildAQuery(name)
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n > 12
}

// buildAQuery builds a minimal DNS query packet for one A record.
func buildAQuery(name string) []byte {
	packet := make([]byte, 0, 64)
	packet = append(packet, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0x00, 0x00, 0x01, 0x00, 0x01)
	return packet
}

// cleanupStaleHelper makes sure no helper from a previous run is still holding
// the DNS port. A leftover root process keeps the system pointed at a resolver
// nobody serves, which looks exactly like "登录成功但什么都连不上".
func (a *app) cleanupStaleHelper() {
	pidPath := filepath.Join(a.dir, "tun.pid")
	if !pidFileFresh(pidPath, 30*time.Second) {
		return
	}
	a.tunLogf("发现上一轮遗留的 TUN 进程，先请它退出")
	stopPath := filepath.Join(a.dir, "tun.stop")
	_ = os.WriteFile(stopPath, []byte("stop"), 0o600)
	for i := 0; i < 25; i++ {
		time.Sleep(200 * time.Millisecond)
		if !pidFileFresh(pidPath, 3*time.Second) {
			break
		}
	}
	_ = os.Remove(stopPath)
	if pidFileFresh(pidPath, 2*time.Second) {
		a.tunLogf("遗留进程仍未退出，请手动结束它以恢复 DNS")
	}
}
