package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/model"
)

func TestCallbackFromURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2?code=abc&state=x", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2/?code=abc", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/cas?ticket=ST-1", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/qywechat?code=abc&sfDomain=wechat", true},
		{"https://vpn.example.edu.cn/passport/v1/auth/qywechat?auth_code=abc&sfDomain=wechat", true},
		{"http://vpn.example.edu.cn/passport/v1/auth/httpsOauth2?code=abc", false},
		{"https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2", false},
		{"https://vpn.example.edu.cn/passport/v1/auth/cas", false},
		{"https://vpn.example.edu.cn/portal", false},
	}
	for _, c := range cases {
		if _, ok := callbackFromURL(c.url); ok != c.want {
			t.Errorf("callbackFromURL(%q) = %v, want %v", c.url, ok, c.want)
		}
	}
}

func TestWeComCredentialsNeedNoPassword(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{
			Name: "扫码网关", Server: "vpn.example.edu.cn", Username: "",
			AuthMode: string(model.AuthModeWeCom), InPool: true,
		})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	creds, err := a.credentials(id)
	if err != nil {
		t.Fatalf("credentials: %v", err)
	}
	if creds.Login != "" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin == nil {
		t.Error("WeCom point has no external login")
	}
}

func TestPasswordCredentials(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.editor.authModeLabel = model.AuthModePassword.Label()
	a.editor.username = "alice"
	a.editor.cred = "pw-for-test"
	a.saveEditor()
	p := a.store.Config().Points[0]
	creds, err := a.credentials(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Login != "pw-for-test" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin != nil {
		t.Error("password point got an external login")
	}
}

func TestExternalLoginMessage(t *testing.T) {
	// The main window is nil in this test app, so the connector's promise
	// is reported instead of trying to open a window.
	a := testApp(t)
	_, err := a.externalLogin(context.Background(), "网关", "vpn.example.edu.cn", "https://vpn.example.edu.cn/login", false)
	if err == nil {
		t.Fatal("externalLogin succeeded without a window")
	}
	if !strings.Contains(err.Error(), "主窗口") {
		t.Errorf("error = %v", err)
	}
}

func TestAutoCredentialsNeedNoPassword(t *testing.T) {
	a := testApp(t)
	var id string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		p := cfg.Add(model.AccessPoint{
			Name: "自动网关", Server: "vpn.example.edu.cn",
			AuthMode: string(model.AuthModeAuto), InPool: true,
		})
		id = p.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	creds, err := a.credentials(id)
	if err != nil {
		t.Fatal(err)
	}
	if creds.Login != "" {
		t.Errorf("login = %q", creds.Login)
	}
	if creds.ExternalLogin == nil {
		t.Error("auto point has no external login")
	}
}

func TestSaveAutoEditor(t *testing.T) {
	a := testApp(t)
	a.openNewEditor()
	a.editor.address = "https://vpn.example.edu.cn"
	a.saveEditor()
	if a.editor.err != "" {
		t.Fatalf("save: %s", a.editor.err)
	}
	p := a.store.Config().Points[0]
	if p.AuthMode != string(model.AuthModeAuto) {
		t.Errorf("auth mode = %q", p.AuthMode)
	}
}

func TestParseQyWechatPoll(t *testing.T) {
	poll, err := parseQyWechatPoll([]byte(`jsonpCallback({"status":"QRCODE_SCAN_SUCC","auth_code":"abc","redirect_uri":"https://vpn.example.edu.cn/cb"})`))
	if err != nil || poll.Status != "QRCODE_SCAN_SUCC" || poll.AuthCode != "abc" {
		t.Fatalf("poll = %+v, %v", poll, err)
	}
	poll, err = parseQyWechatPoll([]byte(`{"status":"QRCODE_SCAN_NEVER"}`))
	if err != nil || poll.Status != "QRCODE_SCAN_NEVER" {
		t.Fatalf("plain poll = %+v, %v", poll, err)
	}
}

func TestQyWechatCallback(t *testing.T) {
	settings := qyWechatSettings{
		AppID: "wxapp", State: "state1", CodeType: 0,
	}
	got, err := qyWechatCallback("https://vpn.example.edu.cn/passport/v1/auth/qywechat?sfDomain=wechat", settings, "code1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("code") != "code1" || q.Get("state") != "state1" || q.Get("appid") != "wxapp" || q.Get("sfDomain") != "wechat" {
		t.Errorf("callback = %s", got)
	}

	settings.CodeType = 1
	got, _ = qyWechatCallback("https://vpn.example.edu.cn/cb", settings, "code1")
	if u, _ := url.Parse(got); u.Query().Get("auth_code") != "code1" {
		t.Errorf("service callback = %s", got)
	}
}

func TestIsQyWechatLoginURL(t *testing.T) {
	if !isQyWechatLoginURL("https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=x") {
		t.Error("qrConnect not recognized")
	}
	if isQyWechatLoginURL("https://open.work.weixin.qq.com/other") {
		t.Error("other page recognized")
	}
	if isQyWechatLoginURL("https://vpn.example.edu.cn/portal") {
		t.Error("vpn page recognized")
	}
}

func TestWWCallback(t *testing.T) {
	s := wwLoginSettings{
		RedirectURI: "https://vpn.example.edu.cn/passport/v1/auth/qywechat?sfDomain=wechat",
		State:       "st1", AppID: "wx1",
	}
	got := wwCallback(s, "code1")
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("code") != "code1" || q.Get("state") != "st1" || q.Get("sfDomain") != "wechat" {
		t.Errorf("callback = %s", got)
	}
	if !callbackFromURLAllowed(got, "vpn.example.edu.cn") {
		t.Errorf("callback not accepted: %s", got)
	}
}

func TestIsWWLoginURL(t *testing.T) {
	if !isWWLoginURL("https://login.work.weixin.qq.com/wwlogin/sso/login?x=1") {
		t.Error("wwlogin not recognized")
	}
	if isWWLoginURL("https://open.work.weixin.qq.com/wwopen/sso/qrConnect") {
		t.Error("qr page misclassified")
	}
}

func TestLandedOnPortal(t *testing.T) {
	const server = "zeroportal.example.net"
	cases := []struct {
		url  string
		want bool
	}{
		{"https://zeroportal.example.net:8888/portal/", true},
		{"https://zeroportal.example.net/portal", true},
		{"https://zeroportal.example.net/portal/shortcut.html", true},
		{"https://zeroportal.example.net/passport/v1/auth/cas?ticket=ST-1", false},
		{"https://zeroportal.example.net/passport/v1/public/casLogin", false},
		{"https://idaas.example.cn/login", false},
		{"http://zeroportal.example.net/portal/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := landedOnPortal(c.url, server); got != c.want {
			t.Errorf("landedOnPortal(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}

func TestCallbackFromURLTakesTicketAndCode(t *testing.T) {
	cas := "https://a.example.net/passport/v1/auth/cas?sfDomain=cas1&ticket=ST-42"
	raw, ok := callbackFromURL(cas)
	if !ok || raw != cas {
		t.Fatalf("cas callback: %q %v", raw, ok)
	}
	if _, ok := callbackFromURL("https://a.example.net/passport/v1/auth/cas?sfDomain=cas1"); ok {
		t.Fatal("没有 ticket 不应算回调")
	}
	if _, ok := callbackFromURL("https://a.example.net/portal/"); ok {
		t.Fatal("门户页不应算回调")
	}
}

func TestParsePageURLs(t *testing.T) {
	got := parsePageURLs(`["https://a.net/portal/","https://a.net/passport/v1/auth/cas?ticket=ST-1"]`)
	if len(got) != 2 || got[1] == "" {
		t.Fatalf("got %v", got)
	}
	if parsePageURLs("") != nil || parsePageURLs(42) != nil {
		t.Fatal("非法输入应返回 nil")
	}
	if parsePageURLs("not json") != nil {
		t.Fatal("坏 JSON 应返回 nil")
	}
}

func TestParsePasteProbe(t *testing.T) {
	href, text := parsePasteProbe(`["https://a.net/x#devtools","https://a.net/passport/v1/auth/cas?ticket=1"]`)
	if !strings.Contains(href, "#devtools") || !strings.HasPrefix(text, "https://") {
		t.Fatalf("href=%q text=%q", href, text)
	}
	if h, x := parsePasteProbe("nope"); h != "" || x != "" {
		t.Fatal("坏输入应返回空")
	}
}

func TestHostSet(t *testing.T) {
	h := &hostSet{hosts: map[string]bool{}}
	h.add("ZeroPortal.Example.Net")
	if !h.has("zeroportal.example.net") || !h.has("ZEROPORTAL.EXAMPLE.NET") {
		t.Fatal("主机名应大小写无关")
	}
	if h.has("idaas.example.cn") {
		t.Fatal("未访问的主机不应放行")
	}
	h.add("")
	if len(h.hosts) != 1 {
		t.Fatalf("空主机不应记录：%v", h.hosts)
	}
}
