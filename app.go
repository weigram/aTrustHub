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
const appBuild = "0.15.0"

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
	// Global TUN state.
	tunOn  bool
	tunPID int
	tunID  string
	// tunWanted is the remembered switch position: after a restart, TUN is
	// resumed for this point once it logs in, so the switch reflects intent.
	tunWanted      bool
	tunResumeTried bool
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
	err           string
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
	mygo.App.OnSecondInstance(func([]string, string) {
		if a.win != nil {
			a.win.Show()
			a.win.Focus()
		}
	})
	mygo.App.WhenReady(a.start)
	mygo.App.OnBeforeQuit(func(e *mygo.QuitEvent) { a.shutdown() })
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
	if f, err := os.Create(logPath); err == nil {
		a.logFile = f
	}
	a.cfg = st.Config()
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

func (a *app) start() {
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
	// ZJU-Connect logs through the standard logger. Show its lines in the
	// app's own log panel, with the time the bus adds, not two timestamps.
	log.SetFlags(0)
	a.bus.SetSink(a.logFile)
	log.SetOutput(a.bus.Writer("zju"))
	a.bus.SetNotify(a.invalidate)
	go a.tailAccessLog()
	a.mgr.Start()
}

func (a *app) shutdown() {
	a.shutdownOnce.Do(func() {
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
		name, server := point.Name, point.Server
		external = func(ctx context.Context, loginURL string) (string, error) {
			return a.externalLogin(ctx, name, server, loginURL)
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
	a.toast = "已复制：" + text
	a.invalidate()
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
