// easyConnect logs in to several aTrust access points at the same time and
// serves one SOCKS5 proxy for each of them and one over all of them. It is
// a mygo desktop app, and the VPN side is ZJU-Connect's aTrust client.
package main

import (
	"sync/atomic"
	"time"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
const appBuild = "0.26.7"

type app struct {
	win   *mygo.Window
	store *store.Store
	mgr   *vpn.Manager
	bus   *vpn.LogBus
	cfg   model.Config
	dir   string
	icon  ui.ImageSource
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
	browserLogin  bool
	monitor       bool
	monitorEvery  string
	secretStore   string
	clearTOTP     bool
	hasPassword   bool
	hasTOTP       bool
	detected      []string
	detecting     bool
	detectGen     int
	detectErr     string
	err           string
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
		store:    st,
		dir:      dir,
		bus:      vpn.NewLogBus(600),
		loginSem: make(chan struct{}, 1),
		icon:     loadAppIcon(),
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
	a.mgr.Start()

	// A slow tick makes TUN follow the online set even when no log line or
	// click happens to trigger a repaint.
	go func() {
		last := time.Now()
		for range time.Tick(3 * time.Second) {
			a.maybeRefreshTUN()
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
		if a.tunOn {
			a.stopTUNQuiet()
			a.tunOn = false
		}
		// Leaving the system proxy pointed at a dead port would cut the
		// machine off, so turn it back off before quitting.
		if a.sysProxyOn {
			_ = applySystemProxy("127.0.0.1:0", false)
			a.sysProxyOn = false
		}
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

// maybeResumeTUN re-opens global TUN once, at startup, for the remembered
// point when it has logged in, so a remembered switch position actually
// resumes. It never touches login itself.
func (a *app) maybeResumeTUN() {
	if !a.tunWanted || a.tunOn || a.tunResumeTried {
		return
	}
	id := a.cfg.Settings.TunPointID
	if id == "" {
		return
	}
	v, ok := a.mgr.View(id)
	if !ok || v.State != vpn.StateOnline {
		return
	}
	a.tunResumeTried = true
	go a.startGlobalTUN(id)
}

// credentials reads what the manager needs for one login.
func (a *app) credentials(id string) (vpn.Credentials, error) {
	point := a.cfg.Find(id)
	mode := model.AuthModePassword
	if point != nil {
		mode = model.AuthMode(point.AuthMode)
	}
	var external func(context.Context, string) (string, error)
	if point != nil && (mode == model.AuthModeAuto || mode == model.AuthModeWeCom) {
		name, server, inBrowser := point.Name, point.Server, point.LoginInBrowser
		external = func(ctx context.Context, loginURL string) (string, error) {
			return a.externalLogin(ctx, name, server, loginURL, inBrowser)
		}
	}
	if mode == model.AuthModeWeCom {
		if external == nil {
			return vpn.Credentials{}, vpn.ErrNoCredentials
		}
		return vpn.Credentials{ExternalLogin: external}, nil
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
