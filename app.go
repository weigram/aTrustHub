// easyConnect logs in to several aTrust access points at the same time and
// serves one SOCKS5 proxy for each of them and one over all of them. It is
// a mygo desktop app, and the VPN side is ZJU-Connect's aTrust client.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/store"
	"github.com/qy/easyconnect/internal/vpn"
)

// version is the app's version.
const version = "0.1.0"

// app is everything the window shows and the manager that does the work.
// appBuild is shown in the footer and the startup log so an old running
// instance is easy to tell apart from a freshly built one.
const appBuild = "0.26.15"

type app struct {
	win   *mygo.Window
	store *store.Store
	mgr   *vpn.Manager
	bus   *vpn.LogBus
	cfg   model.Config
	dir   string
	// keepAlive 记住每个隧道连续探测失败的次数。
	keepAlive tunKeepAlive
	icon      ui.ImageSource
	// qr is the running WeCom QR login drawn in the main window, if any.
	// (qr field removed: WeCom QR login uses a WebView popup now.)
	// sysProxyOn is whether the app turned the macOS system proxy on.
	sysProxyOn bool
	// tray is the notification-area icon that keeps the app alive when the
	// window is closed (Windows), and quitRequested says a quit is intended.
	tray          *mygo.Tray
	quitRequested bool
	// heartbeatOnce keeps one goroutine refreshing the helper's alive file.
	heartbeatOnce sync.Once
	// Global TUN state.
	tunOn  bool
	tunPID int
	tunID  string
	// tunWanted is the remembered switch position: after a restart, TUN is
	// resumed for this point once it logs in, so the switch reflects intent.
	tunWanted      bool
	tunResumeTried bool
	// tunResumeAt throttles restoring the remembered switch position, so a
	// helper that cannot start is not retried on every tick.
	tunResumeAt time.Time
	// tunResumeFails stops the automatic restore after repeated failures; a
	// fresh login or a switch flip clears it.
	tunResumeFails int
	// probeMu serialises tunnel probes: the helper answers one request file,
	// and two parallel tests would overwrite each other's request.
	probeMu sync.Mutex
	// browserLoginMu keeps one browser login at a time: a second one would
	// launch a browser on a profile the first one already holds.
	browserLoginMu sync.Mutex
	// loginPage is the page of the login window on screen, so the menu can open
	// its developer tools.
	loginPage   *mygo.Page
	loginPageMu sync.Mutex
	// logoutAsk holds the point waiting for the "forget authentication"
	// confirmation.
	logoutAsk string
	// quitAsk shows the confirmation before the app really exits.
	quitAsk bool
	// update holds the newer release found at startup, if any.
	update *updateInfo
	// tunPoints is the online-point snapshot the helper was started with.
	tunPoints string
	// tunDiag rate-limits the rebuild diagnostics to state changes.
	tunDiag string
	// tunGate makes sure only one automatic rebuild runs at a time.
	tunGate atomic.Bool
	// tunSeq serializes starting and stopping the helper.
	tunSeq sync.Mutex
	// Mirrors of the TUN state, so a background goroutine can read it without
	// hopping to the UI thread (win.Update from a plain goroutine can block).
	tunOnA      atomic.Bool
	tunPendingA atomic.Bool
	tunPointsA  atomic.Value
	tunIDA      atomic.Value
	// tunPending is true while a start/stop is in flight, so the switch keeps
	// the position the user chose until the async result lands.
	tunPending bool
	// tunSwitch / sysProxySwitch are the switch bindings (see the view).
	tunSwitch      bool
	sysProxySwitch bool

	// editor is the add/edit dialog.
	editor editorDraft
	// settings is the settings dialog.
	settings settingsDraft
	// deleting is the ID whose deletion the app asks about.
	deleting string

	logsOpen bool
	toast    string
	logFile  *os.File

	// tab is 0 for the access points and 1 for the application workbench.
	tab int
	// appQuery filters the workbench.
	appQuery string
	// appSwitch holds one stable boolean per application for its switch:
	// binding a widget to a local makes the click write to a dead address.
	appSwitch map[string]*bool
	// appFilter narrows the workbench to enabled or disabled applications:
	// "all", "on" or "off". appFilterIndex is the segmented control's choice.
	appFilter      string
	appFilterIndex int
	// appCollapsed remembers which access points' app groups are collapsed
	// (true = collapsed). A point is expanded by default.
	appCollapsed map[string]bool
	// detailOpen shows one application's details.
	detailOpen    bool
	detailApp     vpn.App
	detailPoint   string
	detailPointID string
	appTestFor    string
	appTestMsg    string
	appTesting    bool

	// loginSem holds the one WeCom login window; see externalLogin.
	loginSem chan struct{}

	shutdownOnce sync.Once
}

type editorDraft struct {
	open          bool
	editingID     string
	name          string
	address       string
	username      string
	authMode      string
	authModeLabel string
	cred          string
	totp          string
	domain        string
	socksPort     string
	inPool        bool
	autoConnect   bool
	// autoPick lets detection choose the auth mode: what a point saved by an
	// older version (mode "auto") gets when it is opened.
	autoPick     bool
	monitor      bool
	monitorEvery string
	secretStore  string
	clearTOTP    bool
	hasPassword  bool
	hasTOTP      bool
	detected     []string
	detecting    bool
	detectGen    int
	detectErr    string
	err          string
}

type settingsDraft struct {
	open          bool
	host          string
	port          string
	interval      string
	routing       string
	aggregate     bool
	autoReconnect bool
	secretStore   string
	// hideDock hides the macOS Dock icon; the menu bar icon takes over.
	hideDock bool
	err      string
}

func main() {
	mygo.App.SetName("aTrust Hub")
	mygo.App.SetVersion(version)
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}

	a, err := newApp()
	if err != nil {
		log.Fatalf("aTrust Hub: %v", err)
	}
	// Clicking the Dock icon with the window hidden reopens it.
	mygo.App.OnActivate(func(hasVisibleWindows bool) {
		if !hasVisibleWindows {
			a.showWindow()
		}
	})
	mygo.App.OnSecondInstance(func([]string, string) { a.showWindow() })
	mygo.App.WhenReady(a.start)
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) {
		// Cmd+Q and the Dock's 退出 land here too. Ask once, then let the
		// confirmed quit through. If a dialog is already open the request came
		// from the system (logout, shutdown), so do not block it.
		if !a.quitRequested && !a.quitAsk {
			e.PreventDefault()
			a.askQuit()
			return
		}
		a.shutdown()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func newApp() (*app, error) {
	dir, err := resolveDataDir()
	if err != nil {
		return nil, err
	}
	fileSecrets, err := store.NewFileSecrets(dir)
	if err != nil {
		return nil, err
	}
	// Which secret store to use is a setting; read it before opening the
	// store, since the store takes it at construction.
	useKeychain := false
	if b, rerr := os.ReadFile(filepath.Join(dir, "config.json")); rerr == nil {
		var pre struct {
			Settings struct {
				SecretStore string `json:"secretStore"`
			} `json:"settings"`
		}
		if json.Unmarshal(b, &pre) == nil && pre.Settings.SecretStore == model.SecretStoreKeychain {
			useKeychain = true
		}
	}
	var secrets store.SecretStore = fileSecrets
	if useKeychain {
		secrets = store.FallbackSecrets{Primary: keychainSecrets{}, Fallback: fileSecrets}
	}
	st, err := store.Open(dir, secrets)
	if err != nil {
		return nil, err
	}

	a := &app{
		store:     st,
		dir:       dir,
		bus:       vpn.NewLogBus(600),
		loginSem:  make(chan struct{}, 1),
		icon:      loadAppIcon(),
		appSwitch: map[string]*bool{},
		appFilter: "all",
	}
	logPath := os.Getenv("EASYCONNECT_LOG")
	if logPath == "" {
		logPath = filepath.Join(dir, "app.log")
	}
	// Panics print to stderr, which goes nowhere when the app is started from
	// Finder. Point the descriptor at a file so a crash is never a mystery.
	if errF, err := os.OpenFile(filepath.Join(dir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		redirectStderr(errF)
	}

	// Append, not truncate: restarting the app used to wipe the record of what
	// went wrong right before the restart. Keep the file at a sane size.
	if st, err := os.Stat(logPath); err == nil && st.Size() > 4<<20 {
		_ = os.Rename(logPath, logPath+".1")
	}
	if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		a.logFile = f
	}
	a.cfg = st.Config()
	a.sysProxyOn = systemProxyEnabled()
	a.tunWanted = a.cfg.Settings.TunEnabled
	a.bus.Add("app", fmt.Sprintf("aTrust Hub %s 启动，数据目录 %s", appBuild, dir))
	a.mgr = vpn.NewManager(
		vpn.NewZJUConnector(vpn.ZJUOptions{
			DataDir: dir,
			Debug:   os.Getenv("EASYCONNECT_DEBUG") != "",
		}),
		a.credentials,
		a.bus,
		a.invalidate,
	)
	a.mgr.Apply(a.cfg)
	a.cleanupStaleDNS()
	return a, nil
}

// loadAppIcon reads the icon mygo packages as resources/icon.png, for the
// window header. The Dock icon comes from the same file at build time.
func loadAppIcon() ui.ImageSource {
	var paths []string
	if dir, err := mygo.App.Path(mygo.PathResources); err == nil && dir != "" {
		paths = append(paths, filepath.Join(dir, "icon.png"))
	}
	paths = append(paths, filepath.Join("resources", "icon.png"))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if src, err := ui.DecodeBitmap(data); err == nil {
			return src
		}
	}
	return nil
}

func resolveDataDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("EASYCONNECT_HOME")); dir != "" {
		return dir, os.MkdirAll(dir, 0o700)
	}
	if dir, err := mygo.App.Path(mygo.PathUserData); err == nil && dir != "" {
		return dir, os.MkdirAll(dir, 0o700)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "aTrustHub")
	return dir, os.MkdirAll(dir, 0o700)
}

// setupMenu installs the app menu. It keeps the usual App/Edit/Window menus
// and adds a 视图 menu whose 开发者工具 item (F12) opens the login window's
// inspector on request.
func (a *app) setupMenu() {
	menu := mygo.NewMenu([]*mygo.MenuItem{
		{Role: mygo.RoleAppMenu},
		{Role: mygo.RoleEditMenu},
		{Label: "视图", Submenu: []*mygo.MenuItem{
			{Label: "开发者工具（登录窗口）", Accelerator: "F12", Click: func(*mygo.MenuItem, *mygo.Window) {
				a.openLoginDevTools()
			}},
			{Label: "开发者工具", Accelerator: "CmdOrCtrl+Shift+I", Click: func(*mygo.MenuItem, *mygo.Window) {
				a.openLoginDevTools()
			}},
			mygo.Separator(),
			{Role: mygo.RoleViewMenu},
		}},
		{Role: mygo.RoleWindowMenu},
	})
	mygo.App.SetMenu(menu)
}

// setLoginPage records (or clears) the page of the login window on screen.
func (a *app) setLoginPage(p *mygo.Page) {
	a.loginPageMu.Lock()
	a.loginPage = p
	a.loginPageMu.Unlock()
}

// openLoginDevTools opens the developer tools of the login window: what F12 in
// the 视图 menu does. Opening it unprompted froze the whole app, so the user
// asks for it.
func (a *app) openLoginDevTools() {
	a.loginPageMu.Lock()
	p := a.loginPage
	a.loginPageMu.Unlock()
	if p == nil {
		a.toast = "先打开一个接入点的登录窗口"
		a.win.Update(func() {})
		return
	}
	p.OpenDevTools()
}

func (a *app) start() {
	a.createWindow()

	// ZJU-Connect logs through the standard logger. Show its lines in the
	// app's own log panel, with the time the bus adds, not two timestamps.
	log.SetFlags(0)
	a.bus.SetSink(a.logFile)
	a.bus.Add("app", fmt.Sprintf("aTrust Hub %s 启动（窗口就绪），数据目录 %s", appBuild, a.dir))
	log.SetOutput(a.bus.Writer("zju"))
	a.bus.SetNotify(a.invalidate)
	go a.tailAccessLog()
	a.mgr.SetDataDir(a.dir)
	// 上一轮如果被强杀，root helper 可能还占着 127.0.0.1:53。
	a.cleanupStaleHelper()
	a.mgr.Start()

	// A slow tick makes TUN follow the online set even when no log line or
	// click happens to trigger a repaint.
	go func() {
		last := time.Now()
		lastDNSCheck := time.Now()
		dnsFails := 0
		for range time.Tick(3 * time.Second) {
			a.maybeRefreshTUN()
			a.checkTunnels()
			a.guardSystemProxy()
			// TUN 把系统 DNS 指向自己；它一旦不应答，整台机器就上不了网。
			// 连续两次检查失败就主动关掉 TUN，把网络还给系统。
			if a.tunOn && time.Since(lastDNSCheck) > 20*time.Second {
				lastDNSCheck = time.Now()
				if a.tunPoints != "" {
					name := a.dnsProbeName(firstPointID(a.tunPoints))
					if helperAnswersDNS(3*time.Second, name) {
						dnsFails = 0
					} else {
						dnsFails++
						a.tunLogf("DNS 自检失败（%d/3，探测 %s）", dnsFails, name)
						if dnsFails >= 3 {
							dnsFails = 0
							a.tunLogf("TUN 的 DNS 不再应答，自动关闭 TUN 以恢复系统网络")
							go a.stopTUNSerialized()
							a.win.Update(func() {
								a.toast = "TUN 的 DNS 停止应答，已自动关闭 TUN 以恢复网络"
							})
						}
					}
				}
			}
			if time.Since(last) > 60*time.Second {
				last = time.Now()
				a.tunLogf("巡检：on=%v pending=%v 已建=%q 当前=%q", a.tunOn, a.tunPending, a.tunPoints, a.onlineSnapshot())
			}
		}
	}()

	// Ask GitHub for a newer release in the background, so a blocked mirror
	// can never hold up the window.
	a.setupMenu()
	// Desktop quick-login diagnostics go to the same log the user reads.
	wecomLogHook = func(line string) { a.bus.Add("app", line) }
	go a.checkForUpdate()

	// Make sure the first window is on screen even if the remembered state or
	// an early activation left it hidden.
	a.win.Show()
	a.win.Focus()
}

// createWindow builds the main window and its handlers. It runs again when a
// stale window was destroyed, so the app can always be reopened.
func (a *app) createWindow() {
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:           "aTrust Hub",
		Width:           1120,
		Height:          780,
		MinWidth:        860,
		MinHeight:       560,
		StateKey:        "main",
		BackgroundColor: "light-dark(#f7f7f9, #17181a)",
		Content:         ui.View(a.view),
	})
	// Closing the window hides it instead of quitting: tunnels, TUN and the
	// tray/menu bar icon stay alive. Only 退出 really quits.
	a.win.OnClose(func(e *mygo.CloseEvent) {
		a.tunLogf("OnClose: quitRequested=%v", a.quitRequested)
		if a.quitRequested {
			return
		}
		e.PreventDefault()
		a.win.Hide()
		a.updateDockVisibility(true)
	})
	// A window on screen means a Dock icon, whatever the closing behaviour is.
	a.updateDockVisibility(false)
	a.startupTray()
}

func (a *app) shutdown() {
	a.shutdownOnce.Do(func() {
		// A real quit: window closes must go through, or macOS cancels the
		// termination and the process stays alive with no usable UI.
		a.quitRequested = true
		// 退出时两件事必须做到：TUN 的 utun/路由/DNS 全部还原，系统代理关掉。
		// 否则用户下次开机就是「没网」，而且看不出是谁干的。
		a.teardownTUNOnExit()
		a.disableSystemProxyOnExit()
		if a.mgr != nil {
			a.mgr.Close()
		}
		if a.logFile != nil {
			_ = a.logFile.Close()
		}
	})
}

func (a *app) invalidate() {
	if a.win != nil {
		a.win.Invalidate()
	}
	a.maybeResumeTUN()
	a.maybeRefreshTUN()
}

// maybeResumeTUN re-opens global TUN whenever the remembered switch position
// is "on" and an access point is online again. The position is recorded when
// the switch is flipped, so turning TUN off survives a restart and a new login,
// while turning it on means the next login brings it back.
func (a *app) maybeResumeTUN() {
	if !a.tunWanted || a.tunOn || a.tunPending {
		return
	}
	if time.Now().Before(a.tunResumeAt) {
		return
	}
	if a.tunResumeFails >= 3 {
		return
	}
	id := pickResumePoint(a.cfg.Settings.TunPointID, a.mgr.Views())
	if id == "" {
		// 没有在线接入点：把失败计数清零，等下一次登录再试。
		a.tunResumeFails = 0
		return
	}
	a.tunResumeAt = time.Now().Add(30 * time.Second)
	a.tunResumeFails++
	a.tunLogf("按上次的状态恢复全局 TUN（%s，第 %d 次尝试）", id, a.tunResumeFails)
	go a.startGlobalTUN(id)
}

// credentials reads what the manager needs for one login.
//
// The flow follows the configured auth mode, so the same "登录" button
// works everywhere: the password mode signs in by itself, WeCom opens the
// QR popup, and third-party SSO resumes the session the browser login
// saved.
func (a *app) credentials(id string) (vpn.Credentials, error) {
	point := a.cfg.Find(id)
	mode := model.AuthModePassword
	if point != nil && point.AuthMode != "" {
		mode = model.AuthMode(point.AuthMode)
	}
	var external func(context.Context, string) (string, error)
	if point != nil && (mode == model.AuthModeAuto || mode == model.AuthModeWeCom) {
		name, server := point.Name, point.Server
		// WeCom always uses the app's own popup now. Only a legacy "auto"
		// point keeps the old "hand over to the system browser" switch.
		inBrowser := mode == model.AuthModeAuto && point.LoginInBrowser
		external = func(ctx context.Context, loginURL string) (string, error) {
			cb, err := a.externalLogin(ctx, name, server, loginURL, inBrowser)
			if errors.Is(err, errWeComLocalUnavailable) && point != nil && browserExecutable() != "" {
				// 客户端只把本地桥开放给浏览器，本程序直接连会被重置；这时
				// 交给真实浏览器，页面自己会去敲本地桥并弹确认框。
				a.tunLogf("[%s] 本地企业微信认证不可用，改用系统浏览器完成", name)
				return a.cdpLoginCallback(ctx, point, loginURL)
			}
			return cb, err
		}
	}
	switch mode {
	case model.AuthModeWeCom:
		if external == nil {
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{ExternalLogin: external}, nil
	case model.AuthModeSSO:
		// 这里没有账号密码：由真正的浏览器走完单点登录并交回授权码，
		// 登录本身仍由客户端完成，隧道才用得上它自己的设备号与签名。
		point := a.cfg.Find(id)
		if browserExecutable() != "" {
			return vpn.Credentials{ExternalLogin: func(cbCtx context.Context, loginURL string) (string, error) {
				return a.cdpLoginCallback(cbCtx, point, loginURL)
			}}, nil
		}
		// 没有 Chromium 时退回应用内置窗口，走同一条单点登录。
		if external != nil {
			return vpn.Credentials{ExternalLogin: external}, nil
		}
		return vpn.Credentials{}, nil
	}

	cred, err := a.store.Password(id)
	if err != nil {
		if strings.Contains(err.Error(), "User canceled") || strings.Contains(err.Error(), "-128") {
			return vpn.Credentials{}, errors.New("读取密码失败：钥匙串访问被取消。请重新登录，并在系统弹窗点「允许」，或编辑接入点重新输入密码")
		}
		if errors.Is(err, store.ErrSecretNotFound) {
			if mode == model.AuthModeAuto {
				// Auto can still use an external login.
				return vpn.Credentials{ExternalLogin: external}, nil
			}
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{}, err
	}
	totp, err := a.store.TOTP(id)
	if err != nil && !errors.Is(err, store.ErrSecretNotFound) {
		return vpn.Credentials{}, err
	}
	return vpn.Credentials{Login: cred, TOTP: totp, ExternalLogin: external}, nil
}

func (a *app) hasPassword(id string) bool {
	_, err := a.store.Password(id)
	return err == nil
}

func (a *app) hasTOTP(id string) bool {
	_, err := a.store.TOTP(id)
	return err == nil
}

// saveConfig writes the in-memory configuration and tells the manager.
func (a *app) saveConfig() error {
	if err := a.store.Save(); err != nil {
		return err
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	return nil
}

func (a *app) copyText(text string) {
	if text == "" {
		return
	}
	if err := mygo.Clipboard.Write(transfer.TextData(text)); err != nil {
		a.toast = "复制失败：" + err.Error()
		a.invalidate()
		return
	}
	// Keep the notice short: showing the copied text itself made the toast
	// cover the window when a whole log was copied.
	if lines := strings.Count(text, "\n") + 1; lines > 1 {
		a.toast = fmt.Sprintf("已复制 %d 行", lines)
	} else {
		a.toast = "已复制：" + shortText(text, 40)
	}
	a.invalidate()
}

// shortText clips s for a one-line notice.
func shortText(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}

func (a *app) describeProgress() string {
	online, connecting, total := a.mgr.Counts()
	switch {
	case total == 0:
		return "还没有接入点"
	case connecting > 0:
		return fmt.Sprintf("%d 个在线，%d 个登录中", online, connecting)
	default:
		return fmt.Sprintf("%d / %d 个在线", online, total)
	}
}

// guardSystemProxy turns the system proxy back off when the unified entry it
// points at is no longer listening. Leaving it on would cut the whole machine
// off, which is worse than losing the VPN.
func (a *app) guardSystemProxy() {
	if !a.sysProxyOn {
		return
	}
	agg := a.mgr.Aggregate()
	if agg.Running && agg.Addr != "" {
		if conn, err := net.DialTimeout("tcp", agg.Addr, 1500*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
	}
	_ = applySystemProxy("127.0.0.1:0", false)
	a.sysProxyOn = false
	a.sysProxySwitch = false
	a.tunLogf("统一入口已停止监听，已自动关闭系统代理以恢复网络")
	a.win.Update(func() { a.toast = "统一入口已停止，已自动关闭系统代理" })
}

// firstPointID returns the first id of a comma-joined snapshot.
func firstPointID(snapshot string) string {
	for _, id := range strings.Split(snapshot, ",") {
		if id = strings.TrimSpace(id); id != "" {
			return id
		}
	}
	return ""
}

// teardownTUNOnExit stops the helper, makes sure the system DNS is not left
// pointing at 127.0.0.1, and clears the control files.
func (a *app) teardownTUNOnExit() {
	pidPath := filepath.Join(a.dir, "tun.pid")
	_, pidErr := os.Stat(pidPath)
	if !a.tunOn && pidErr != nil && a.tunPID <= 0 {
		// 没开过 TUN，但上一次可能被强杀留下了 DNS 劫持，仍然兜底一次。
		a.cleanupStaleDNS()
		return
	}
	// 给 helper 足够时间自己退出：它会在退出前把 DNS 交还系统。
	if !a.shutdownHelper(6 * time.Second) {
		a.tunLogf("退出：helper 未在 6 秒内退出，强制结束后重置 DNS")
	}
	// helper 被强杀时来不及恢复 DNS，这里再兜底一次。
	a.cleanupStaleDNS()
	a.tunOn = false
	a.tunPID = 0
	for _, name := range []string{"tun.stop", "tun.pid", "tun.reload", "tun.probe", "tun.probe.result"} {
		_ = os.Remove(filepath.Join(a.dir, name))
	}
	a.tunLogf("退出：TUN 已清理，DNS 已交还系统")
}

// disableSystemProxyOnExit turns the system proxy off before quitting, retrying
// once because a failed revert leaves the machine with no usable network.
func (a *app) disableSystemProxyOnExit() {
	if !a.sysProxyOn {
		return
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := applySystemProxy("127.0.0.1:0", false); err == nil {
			a.sysProxyOn = false
			a.tunLogf("退出：已关闭系统代理")
			return
		} else {
			a.tunLogf("退出：关闭系统代理失败（第 %d 次）：%v", attempt+1, err)
		}
	}
}
