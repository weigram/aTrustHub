package vpn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"

	"github.com/qy/easyconnect/internal/model"
)

func TestClientDataRoundTrip(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`{"deviceID":"abc","cookies":[{"name":"a","value":"b"}]}`)
	if err := writeClientData(dir, "point1", data); err != nil {
		t.Fatal(err)
	}
	got, err := readClientData(dir, "point1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q", got)
	}
	path := clientDataPath(dir, "point1")
	if !strings.HasSuffix(path, filepath.Join("atrust", "point1.json")) {
		t.Errorf("path = %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o", mode)
	}
}

func TestClientDataMissingAndInvalid(t *testing.T) {
	dir := t.TempDir()
	if data, err := readClientData(dir, "nope"); err != nil || data != nil {
		t.Fatalf("missing gave %q, %v", data, err)
	}
	path := clientDataPath(dir, "bad")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readClientData(dir, "bad"); err != nil || data != nil {
		t.Fatalf("invalid gave %q, %v", data, err)
	}
}

func TestFriendlyConnectError(t *testing.T) {
	if got := friendlyConnectError(context.DeadlineExceeded); !strings.Contains(got, "超时") {
		t.Errorf("deadline = %q", got)
	}
	if got := friendlyConnectError(context.Canceled); !strings.Contains(got, "取消") {
		t.Errorf("canceled = %q", got)
	}
	if got := friendlyConnectError(os.ErrPermission); !strings.Contains(got, "permission") {
		t.Errorf("other = %q", got)
	}
}

func TestConnectToClosedPortFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := NewZJUConnector(ZJUOptions{DataDir: t.TempDir()})(ctx,
		model.AccessPoint{
			ID: "test", Name: "test", Server: "127.0.0.1", Port: 1,
			Username: "alice", LoginDomain: "Radius",
		},
		Credentials{Login: "pw-for-test"},
	)
	if err == nil {
		t.Fatal("login to a closed port succeeded")
	}
}

func TestPickExternalAuthInfo(t *testing.T) {
	infos := []auth.AuthInfo{
		{LoginDomain: "Radius", AuthType: "auth/psw", AuthName: "上网账号"},
		{LoginDomain: "wecom", AuthType: "auth/httpsOauth2", AuthName: "企业微信认证", LoginURL: "https://idp.example/qr"},
		{LoginDomain: "ding", AuthType: "auth/httpsOauth2", AuthName: "钉钉", LoginURL: "https://idp.example/ding"},
	}
	got, ok := pickExternalAuthInfo(infos, "Radius")
	if !ok {
		t.Fatal("no external method")
	}
	if got.AuthName != "企业微信认证" {
		t.Errorf("picked %q", got.AuthName)
	}
}

func TestLoginMethodFromCallback(t *testing.T) {
	info := auth.AuthInfo{LoginDomain: "wecom", AuthType: "auth/httpsOauth2"}
	callback := "https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2?code=abc&state=x"
	method, err := loginMethodFromCallback(info, callback, "vpn.example.edu.cn")
	if err != nil {
		t.Fatal(err)
	}
	oauth, ok := method.(auth.HTTPSOauth2Login)
	if !ok {
		t.Fatalf("method = %T", method)
	}
	if oauth.Callback != callback || oauth.LoginDomain() != "wecom" {
		t.Errorf("method = %+v", oauth)
	}

	if _, err := loginMethodFromCallback(info, callback, "other.example"); err == nil {
		t.Error("callback for another host was accepted")
	}
	if _, err := loginMethodFromCallback(info, "https://vpn.example.edu.cn/passport/v1/auth/httpsOauth2", "vpn.example.edu.cn"); err == nil {
		t.Error("callback without a code was accepted")
	}

	casInfo := auth.AuthInfo{LoginDomain: "wecom", AuthType: "auth/cas"}
	cas, err := loginMethodFromCallback(casInfo, "https://vpn.example.edu.cn/passport/v1/auth/cas?ticket=ST-1", "vpn.example.edu.cn")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cas.(auth.CASLogin); !ok || got.Ticket != "ST-1" {
		t.Errorf("cas = %#v", cas)
	}
}

func TestDescribeAuthInfo(t *testing.T) {
	got := describeAuthInfo([]auth.AuthInfo{{AuthType: "auth/psw", AuthName: "上网账号", LoginDomain: "Radius"}})
	if !strings.Contains(got, "auth/psw") || !strings.Contains(got, "Radius") {
		t.Errorf("describe = %q", got)
	}
}

func TestExternalLoginToClosedPortFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	called := false
	_, err := zjuLoginMethod(ctx, model.AccessPoint{
		ID: "test", Name: "test", Server: "127.0.0.1", Port: 1,
		AuthMode: string(model.AuthModeWeCom),
	}, Credentials{ExternalLogin: func(context.Context, string) (string, error) {
		called = true
		return "", nil
	}})
	if err == nil {
		t.Fatal("external login to a closed port succeeded")
	}
	if called {
		t.Error("the login window was opened without an auth URL")
	}
}

func TestQyWechatLoginURL(t *testing.T) {
	info := auth.AuthInfo{
		LoginDomain: "wechat",
		AuthType:    "auth/qywechat",
		AuthName:    "企业微信认证",
		QyWechatQrcodeConf: auth.QyWechatQrcodeConf{
			AppID:       "ww-app",
			AgentID:     "1000030",
			RedirectURI: "https://vpn.example.edu.cn:44892/passport/v1/auth/qywechat?sfDomain=wechat",
			RequireURL:  "https://qyapi.weixin.qq.com/wwopen/sso/qrConnect",
			State:       "state-1",
		},
	}
	u, err := authLoginURL(info, model.AccessPoint{Server: "vpn.example.edu.cn", Port: 44892})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"open.work.weixin.qq.com", "appid=ww-app", "agentid=1000030", "state=state-1", "redirect_uri="} {
		if !strings.Contains(u, want) {
			t.Errorf("URL %q lacks %q", u, want)
		}
	}

	picked, ok := pickExternalAuthInfo([]auth.AuthInfo{
		{LoginDomain: "local", AuthType: "auth/psw", AuthName: "本地密码认证"},
		info,
	}, "Radius")
	if !ok || picked.AuthType != "auth/qywechat" {
		t.Errorf("picked = %+v, %v", picked, ok)
	}

	callback := "https://vpn.example.edu.cn:44892/passport/v1/auth/qywechat?sfDomain=wechat&code=abc&state=state-1"
	method, err := loginMethodFromCallback(info, callback, "vpn.example.edu.cn")
	if err != nil {
		t.Fatal(err)
	}
	qy, ok := method.(auth.QyWechatLogin)
	if !ok {
		t.Fatalf("method = %T", method)
	}
	if qy.Callback != callback || qy.LoginDomain() != "wechat" {
		t.Errorf("method = %+v", qy)
	}
}

func TestPickPasswordAuthInfo(t *testing.T) {
	infos := []auth.AuthInfo{
		{LoginDomain: "local", AuthType: "auth/psw", AuthName: "Local"},
		{LoginDomain: "Radius", AuthType: "auth/psw", AuthName: "上网账号"},
		{LoginDomain: "wechat", AuthType: "auth/qywechat", AuthName: "企业微信"},
	}
	info, ok := pickPasswordAuthInfo(infos, "Radius")
	if !ok || info.LoginDomain != "Radius" {
		t.Errorf("picked %+v, %v", info, ok)
	}
	info, ok = pickPasswordAuthInfo(infos, "")
	if !ok || info.LoginDomain != "local" {
		t.Errorf("default picked %+v, %v", info, ok)
	}
	if _, ok := pickPasswordAuthInfo(infos[2:], "Radius"); ok {
		t.Error("picked psw from external-only list")
	}
}

func TestAuthMethodLabel(t *testing.T) {
	if got := (AuthMethod{Name: "企业微信认证", Domain: "wechat", Type: "auth/qywechat"}).Label(); got != "企业微信认证（wechat）" {
		t.Errorf("label = %q", got)
	}
	if got := (AuthMethod{Type: "auth/psw"}).Label(); got != "auth/psw" {
		t.Errorf("label = %q", got)
	}
}

func TestSavedSessionIDs(t *testing.T) {
	data := []byte(`{"device_id":"abc123","cookies":[{"name":"lang","value":"zh"},{"name":"sid","value":"SID-9"}]}`)
	sid, dev := savedSessionIDs(data)
	if sid != "SID-9" || dev != "abc123" {
		t.Fatalf("sid=%q dev=%q", sid, dev)
	}
	if sid, dev := savedSessionIDs(nil); sid != "" || dev != "" {
		t.Fatal("空数据应返回空值")
	}
	if sid, dev := savedSessionIDs([]byte("not json")); sid != "" || dev != "" {
		t.Fatal("坏数据应返回空值")
	}
	// 没有 sid 的会话不能当作可复用
	sid, _ = savedSessionIDs([]byte(`{"device_id":"d","cookies":[{"name":"lang","value":"zh"}]}`))
	if sid != "" {
		t.Fatalf("无 sid 时不应返回 %q", sid)
	}
}

func TestReadResourceDump(t *testing.T) {
	dir := t.TempDir()
	if _, err := readResourceDump(dir, "p1"); err == nil {
		t.Fatal("文件不存在时应报错")
	}
	if err := os.MkdirAll(filepath.Join(dir, "atrust"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"data":{"appList":{}}}`)
	if err := os.WriteFile(filepath.Join(dir, "atrust", "p1.resource.json"), want, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readResourceDump(dir, "p1")
	if err != nil || string(got) != string(want) {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
