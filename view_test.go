package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/store"
	"github.com/qy/easyconnect/internal/vpn"
)

type stubSession struct {
	ip   string
	apps []vpn.App
}

func demoApps() []vpn.App {
	return []vpn.App{
		{
			ID: "app-1", Name: "18F-同步通道（软件公司）", Description: "同步通道",
			AccessModel: "L3VPN", GroupName: "默认分类", NodeGroupID: "node-1",
			NodeGroupName: "Default",
			Addresses: []vpn.AppAddress{
				{Protocol: "tcp", Host: "10.18.12.89", Port: "1-65535"},
				{Protocol: "udp", Host: "10.18.12.89", Port: "1-65535"},
			},
		},
		{
			ID: "app-2", Name: "部门管理系统", Description: "部门管理系统",
			AccessModel: "TUN2WEB", GroupName: "单独申请",
			Addresses: []vpn.AppAddress{{Protocol: "tcp", Host: "oa.example", Port: "443"}},
		},
	}
}

func (stubSession) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (s stubSession) Info() vpn.SessionInfo {
	return vpn.SessionInfo{
		ClientIP: s.ip, Apps: s.apps,
		BestNodes: map[string]string{"default": "node1.example:443"},
	}
}
func (stubSession) Close() error { return nil }

func testApp(t *testing.T) *app {
	t.Helper()
	dir := t.TempDir()
	secrets, err := store.NewFileSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	a := &app{
		store: st,
		dir:   dir,
		bus:   vpn.NewLogBus(100),
		icon:  loadAppIcon(),
	}
	a.cfg = st.Config()
	a.mgr = vpn.NewManager(
		func(ctx context.Context, p model.AccessPoint, creds vpn.Credentials) (vpn.Session, error) {
			ip := map[string]string{"主网关": "10.10.1.23", "教育网线路": "10.10.1.24", "备用网关": "10.10.1.25"}[p.Name]
			if ip == "" {
				ip = "10.10.1.23"
			}
			return stubSession{ip: ip, apps: demoApps()}, nil
		},
		a.credentials,
		a.bus,
		a.invalidate,
	)
	t.Cleanup(a.mgr.Close)
	a.mgr.Apply(a.cfg)
	return a
}

func TestEmptyView(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"aTrust Hub", "统一入口", "还没有接入点", "添加第一个接入点"} {
		if !strings.Contains(texts, want) {
			t.Errorf("view lacks %q; texts = %s", want, texts)
		}
	}
}

func TestAddButtonOpensEditor(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 800)
	if err := tt.Click("＋ 添加接入点"); err != nil {
		t.Fatalf("click add: %v", err)
	}
	if !a.editor.open {
		t.Fatal("editor did not open")
	}
	tt.Frame()
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "添加接入点") {
		t.Errorf("editor is not shown: %s", texts)
	}
}

func TestSaveEditor(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.name = "主网关"
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "1081"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	cfg := a.store.Config()
	if len(cfg.Points) != 1 {
		t.Fatalf("points = %+v", cfg.Points)
	}
	p := cfg.Points[0]
	if p.Name != "主网关" || p.Server != "vpn.example.edu.cn" || p.Port != 443 {
		t.Errorf("point = %+v", p)
	}
	if pw, err := a.store.Password(p.ID); err != nil || pw != "pw-for-test" {
		t.Errorf("password = %q, %v", pw, err)
	}
	if a.editor.open {
		t.Error("editor stayed open")
	}

	// The point is on the page after the editor goes away.
	tt := ui.NewTester(a.view, 1120, 800)
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "主网关") {
		t.Errorf("saved point is not shown: %s", texts)
	}
}

func TestSaveEditorRejectsEmptyFields(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.saveEditor()
	if a.editor.err == "" {
		t.Fatal("empty form was accepted")
	}
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModePassword.Label()
	a.editor.username = "alice"
	a.saveEditor()
	if a.editor.err == "" {
		t.Fatal("missing password was accepted")
	}
}

func TestSaveEditorKeepsExistingPassword(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]

	a.openEditor(vpn.View{ID: p.ID})
	if !a.editor.hasPassword {
		t.Fatal("editor does not know the saved password")
	}
	a.editor.name = "改名"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	if pw, _ := a.store.Password(p.ID); pw != "pw-for-test" {
		t.Errorf("password = %q", pw)
	}
	if got := a.store.Config().Points[0].Name; got != "改名" {
		t.Errorf("name = %q", got)
	}
}

func TestPortConflictIsReported(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "1080"
	a.saveEditor()
	if a.editor.err == "" || !strings.Contains(a.editor.err, "统一入口") {
		t.Errorf("conflict gave %q", a.editor.err)
	}
}

func TestSettingsSave(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	a.settings.host = "127.0.0.1"
	a.settings.port = "1088"
	a.settings.interval = "30"
	a.settings.aggregate = false
	a.settings.routing = model.RoutingRoundRobin.Label()
	a.saveSettings()
	if a.settings.err != "" {
		t.Fatalf("save: %s", a.settings.err)
	}
	cfg := a.store.Config()
	if cfg.Settings.AggregatePort != 1088 || cfg.Settings.Routing != model.RoutingRoundRobin {
		t.Errorf("settings = %+v", cfg.Settings)
	}
	if cfg.Settings.AggregateEnabled {
		t.Error("aggregate proxy stayed on")
	}
}

func TestRemovePoint(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	a.removePoint(p.ID)
	if len(a.store.Config().Points) != 0 {
		t.Error("point survived")
	}
	if _, err := a.store.Password(p.ID); !errors.Is(err, store.ErrSecretNotFound) {
		t.Errorf("secret survived: %v", err)
	}
}

func TestDeleteDialog(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	a.deleting = p.ID
	tt := ui.NewTester(a.view, 1120, 800)
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "删除接入点") {
		t.Fatalf("dialog is not shown: %s", texts)
	}
	if err := tt.Click("确认删除"); err != nil {
		t.Fatalf("click delete: %v", err)
	}
	if len(a.store.Config().Points) != 0 {
		t.Error("point survived the dialog")
	}
}

func TestStats(t *testing.T) {
	a := testApp(t)
	if got := a.describeProgress(); !strings.Contains(got, "还没有") {
		t.Errorf("describeProgress = %q", got)
	}
	if a.dir != filepath.Clean(a.dir) {
		t.Error("unclean data dir")
	}
}

func TestZeroSocksPortIsRespected(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "0"
	a.editor.inPool = true
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	if got := a.store.Config().Points[0].SocksPort; got != 0 {
		t.Errorf("socks port = %d, want 0", got)
	}
}

func TestSaveWeComEditor(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModeWeCom.Label()
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.AuthMode != string(model.AuthModeWeCom) {
		t.Errorf("auth mode = %q", p.AuthMode)
	}
	if p.Username != "" {
		t.Errorf("username = %q", p.Username)
	}
	if _, err := a.store.Password(p.ID); !errors.Is(err, store.ErrSecretNotFound) {
		t.Errorf("WeCom point stored a password: %v", err)
	}
}

func TestAppsTab(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "0"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	id := a.store.Config().Points[0].ID
	a.mgr.Connect(id)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, _ := a.mgr.View(id); v.State == vpn.StateOnline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.tab = 1
	tt := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"应用中心", "18F-同步通道", "部门管理系统", "隧道模式（TCP/UDP协议）"} {
		if !strings.Contains(texts, want) {
			t.Errorf("apps tab lacks %q; texts = %s", want, texts)
		}
	}
	if err := tt.Click("应用详情 18F-同步通道（软件公司）"); err != nil {
		t.Fatalf("open detail: %v", err)
	}
	if !a.detailOpen {
		t.Fatal("detail did not open")
	}
	tt.Frame()
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "10.18.12.89:1-65535") {
		t.Errorf("detail lacks address: %s", texts)
	}
}

func TestSaveEditorWithAccessAddress(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.com:44892/portal"
	a.editor.authModeLabel = model.AuthModeWeCom.Label()
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.Server != "vpn.example.com" || p.Port != 44892 {
		t.Errorf("point = %+v", p)
	}

	// Opening the editor shows the same address back.
	a.openEditor(vpn.View{ID: p.ID})
	if a.editor.address != "https://vpn.example.com:44892" {
		t.Errorf("editor address = %q", a.editor.address)
	}
}

func TestProbeHostText(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.editor.socksPort = "0"
	a.saveEditor()
	id := a.store.Config().Points[0].ID
	a.mgr.Connect(id)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, _ := a.mgr.View(id); v.State == vpn.StateOnline {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	line := a.probeHostText(id, "10.20.163.37", []int{443, 80})
	if !strings.HasPrefix(line, "❌") || !strings.Contains(line, "10.20.163.37") {
		t.Errorf("probe line = %q", line)
	}
}
