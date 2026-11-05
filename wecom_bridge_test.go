package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubWeComBridge answers like the desktop client's local bridge: it wants a
// Referer, a JSON body and (optionally) the cookie it handed out first.
type stubWeComBridge struct {
	mu          sync.Mutex
	referers    []string
	checkBody   map[string]any
	confirmBody map[string]any
	loginState  float64
	h2Only      bool
	needCookie  bool
	cookieSeen  bool
}

func (s *stubWeComBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.referers = append(s.referers, r.Header.Get("Referer"))
	s.mu.Unlock()

	if s.h2Only && r.ProtoMajor < 2 {
		w.WriteHeader(http.StatusBadRequest)
		writeStubJSON(w, map[string]any{"data": map[string]any{"statusCode": 400}})
		return
	}

	switch r.URL.Path {
	case "/checkLoginState":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.checkBody = body
		s.mu.Unlock()
		if s.needCookie {
			http.SetCookie(w, &http.Cookie{Name: "ww_bridge", Value: "1", Path: "/"})
		}
		writeStubJSON(w, map[string]any{"data": map[string]any{
			"login_state":         s.loginState,
			"quick_login_enabled": true,
		}})
	case "/confirmLogin":
		if s.needCookie {
			if c, err := r.Cookie("ww_bridge"); err == nil && c.Value == "1" {
				s.mu.Lock()
				s.cookieSeen = true
				s.mu.Unlock()
			} else {
				w.WriteHeader(http.StatusForbidden)
				writeStubJSON(w, map[string]any{"data": map[string]any{
					"statusCode": 403,
					"result":     map[string]any{"errCode": 10050002},
				}})
				return
			}
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.mu.Lock()
		s.confirmBody = body
		s.mu.Unlock()
		writeStubJSON(w, map[string]any{"data": map[string]any{
			"result": map[string]any{"errCode": 0},
		}})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeStubJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func stubPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("监听地址不是 TCP：%v", srv.Listener.Addr())
	}
	return addr.Port
}

const (
	stubLoginURL    = "https://login.work.weixin.qq.com/wwlogin/sso/login?agentid=1"
	stubRedirectURI = "https://access.example.cn:44892/passport/v1/auth/qywechat"
)

func TestBridgeProbePlainTLS(t *testing.T) {
	stub := &stubWeComBridge{loginState: 1}
	srv := httptest.NewTLSServer(stub)
	defer srv.Close()

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "https", port: stubPort(t, srv), mode: bridgePlainTLS},
	}, stubLoginURL, stubRedirectURI)

	if !probe.loggedIn || !probe.reachable {
		t.Fatalf("没能识别已登录的桥：%+v", probe.errors)
	}
	if !client.hasTarget() {
		t.Fatal("探测成功后应当记住目标")
	}
	stub.mu.Lock()
	body := stub.checkBody
	referer := ""
	if len(stub.referers) > 0 {
		referer = stub.referers[0]
	}
	stub.mu.Unlock()
	if body["scene"] != float64(scenePCLogin) {
		t.Fatalf("scene = %v", body["scene"])
	}
	if body["redirect_uri"] != stubRedirectURI {
		t.Fatalf("redirect_uri = %v", body["redirect_uri"])
	}
	if referer != stubLoginURL {
		t.Fatalf("Referer = %q", referer)
	}
}

// TestBridgeProbeChromeHTTP2 covers the Windows client: it drops a handshake
// that offers no ALPN and only answers HTTP/2, so the plain attempt has to
// fail over to the Chrome client hello.
func TestBridgeProbeChromeHTTP2(t *testing.T) {
	stub := &stubWeComBridge{loginState: 1, h2Only: true}
	srv := httptest.NewUnstartedServer(stub)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	port := stubPort(t, srv)

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "https", port: port, mode: bridgePlainTLS},
		{scheme: "https", port: port, mode: bridgeChromeH2},
	}, stubLoginURL, stubRedirectURI)

	if !probe.loggedIn {
		t.Fatalf("HTTP/2 桥没探测到：%+v", probe.errors)
	}
	if got := probe.target.mode; got != bridgeChromeH2 {
		t.Fatalf("应当落到 chrome-h2，实际 %v", got)
	}
}

func TestBridgeProbeHTTPScheme(t *testing.T) {
	stub := &stubWeComBridge{loginState: 1}
	srv := httptest.NewServer(stub)
	defer srv.Close()

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "http", port: stubPort(t, srv)},
	}, stubLoginURL, stubRedirectURI)
	if !probe.loggedIn {
		t.Fatalf("http 端口没探测到：%+v", probe.errors)
	}
}

func TestBridgeProbeReachableButLoggedOut(t *testing.T) {
	stub := &stubWeComBridge{loginState: 0}
	srv := httptest.NewTLSServer(stub)
	defer srv.Close()

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "https", port: stubPort(t, srv), mode: bridgePlainTLS},
	}, stubLoginURL, stubRedirectURI)
	if probe.loggedIn {
		t.Fatal("login_state=0 不应当算已登录")
	}
	if !probe.reachable {
		t.Fatal("桥有响应，应当标记为可达")
	}
}

// TestBridgeBindKeepsCookie checks the two requests run as one session: the
// bridge hands out a cookie when it is probed and expects it back on confirm.
func TestBridgeBindKeepsCookie(t *testing.T) {
	stub := &stubWeComBridge{loginState: 1, needCookie: true}
	srv := httptest.NewTLSServer(stub)
	defer srv.Close()

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "https", port: stubPort(t, srv), mode: bridgePlainTLS},
	}, stubLoginURL, stubRedirectURI)
	if !probe.loggedIn {
		t.Fatalf("探测失败：%+v", probe.errors)
	}
	if _, err := client.bind(context.Background(), stubLoginURL, "client-key-123"); err != nil {
		t.Fatalf("bind: %v", err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if !stub.cookieSeen {
		t.Fatal("确认请求没有带上探测时下发的 cookie")
	}
	if stub.confirmBody["web_key"] != "client-key-123" {
		t.Fatalf("web_key = %v", stub.confirmBody["web_key"])
	}
	if stub.confirmBody["scene"] != float64(scenePCLogin) {
		t.Fatalf("scene = %v", stub.confirmBody["scene"])
	}
}

func TestBridgeBindWithoutTarget(t *testing.T) {
	client := &bridgeClient{}
	if _, err := client.bind(context.Background(), stubLoginURL, "k"); err == nil {
		t.Fatal("没有目标时 bind 应当报错")
	}
}

func TestClickToken(t *testing.T) {
	cases := []struct {
		in    any
		token string
		ok    bool
	}{
		{"#local-1699999999", "local-1699999999", true},
		{"#local-1", "local-1", true},
		{"#browser-1699999999", "browser-1699999999", true},
		{"#browser-", "", false},
		{"", "", false},
		{"#local", "", false},
		{"#local-", "", false},
		{"#other", "", false},
		{nil, "", false},
		{42, "", false},
	}
	for _, c := range cases {
		token, ok := clickToken(c.in)
		if ok != c.ok || token != c.token {
			t.Fatalf("clickToken(%v) = (%q,%v)，想要 (%q,%v)", c.in, token, ok, c.token, c.ok)
		}
	}
}

func TestDedupePorts(t *testing.T) {
	got := dedupePorts([]int{50010, 0, 50010, 70000, -1, 50018})
	want := []int{50010, 50018}
	if len(got) != len(want) {
		t.Fatalf("dedupePorts = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupePorts = %v", got)
		}
	}
}

// TestBridgeRejectReason covers the answer the bridge gives when it does not
// accept the request's origin: it is a refusal, not a logged-out client.
func TestBridgeRejectReason(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{
			name: "referer rejected",
			in: map[string]any{"data": map[string]any{
				"statusCode": float64(403),
				"result": map[string]any{
					"errCode": float64(10050002),
					"errMsg":  "referer verify fail",
				},
			}},
			want: "403 referer verify fail",
		},
		{
			name: "logged in",
			in: map[string]any{"data": map[string]any{
				"login_state": float64(1),
			}},
			want: "",
		},
		{
			name: "errCode only",
			in: map[string]any{"data": map[string]any{
				"result": map[string]any{"errCode": float64(10050002)},
			}},
			want: "10050002",
		},
		{
			name: "no data",
			in:   map[string]any{},
			want: "",
		},
	}
	for _, c := range cases {
		if got := bridgeRejectReason(c.in); got != c.want {
			t.Fatalf("%s: bridgeRejectReason = %q，想要 %q", c.name, got, c.want)
		}
	}
}

// TestBridgeProbeRecordsReject checks a refusal is surfaced instead of being
// reported as "client not logged in".
func TestBridgeProbeRecordsReject(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		writeStubJSON(w, map[string]any{"data": map[string]any{
			"statusCode": 403,
			"result":     map[string]any{"errCode": 10050002, "errMsg": "referer verify fail"},
		}})
	}))
	defer srv.Close()

	client := &bridgeClient{}
	probe := client.probe(context.Background(), []bridgeTarget{
		{scheme: "https", port: stubPort(t, srv), mode: bridgePlainTLS},
	}, stubLoginURL, stubRedirectURI)
	if probe.loggedIn {
		t.Fatal("403 不应当算已登录")
	}
	if probe.reachable {
		t.Fatal("被拒绝的请求不应当算作可达，否则会误报「客户端没登录」")
	}
	if !strings.Contains(probe.reject, "referer verify fail") {
		t.Fatalf("reject = %q", probe.reject)
	}
	if probe.rejectTarget.port != stubPort(t, srv) {
		t.Fatalf("rejectTarget = %v", probe.rejectTarget)
	}
}

// muteListener accepts connections and never answers, like a port that the
// desktop client released and another program now holds.
func muteListener(t *testing.T) (net.Listener, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	return ln, func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	}
}

// TestBridgeProbeSkipsMutePort covers the "port moved" case: a port that is
// taken by something else stays silent, so the other client hellos there are
// skipped instead of each burning a timeout, and the search goes on.
func TestBridgeProbeSkipsMutePort(t *testing.T) {
	mute, closeMute := muteListener(t)
	defer closeMute()
	mutePort := mute.Addr().(*net.TCPAddr).Port

	stub := &stubWeComBridge{loginState: 1}
	srv := httptest.NewTLSServer(stub)
	defer srv.Close()

	targets := []bridgeTarget{
		{scheme: "https", port: mutePort, mode: bridgePlainTLS},
		{scheme: "https", port: mutePort, mode: bridgeChromeH2},
		{scheme: "https", port: mutePort, mode: bridgeChromeH1},
		{scheme: "https", port: mutePort, mode: bridgeGoH2},
		{scheme: "https", port: stubPort(t, srv), mode: bridgePlainTLS},
	}

	start := time.Now()
	client := &bridgeClient{}
	probe := client.probe(context.Background(), targets, stubLoginURL, stubRedirectURI)
	elapsed := time.Since(start)

	if !probe.loggedIn {
		t.Fatalf("没跳过静默端口：%+v", probe.errors)
	}
	if len(probe.errors) != 1 {
		t.Fatalf("静默端口只应留下 1 条错误，实际 %d：%+v", len(probe.errors), probe.errors)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("在静默端口上花了太久：%v", elapsed)
	}
}

func TestBridgeTimedOut(t *testing.T) {
	if !bridgeTimedOut(context.DeadlineExceeded) {
		t.Fatal("DeadlineExceeded 应当算超时")
	}
	if bridgeTimedOut(net.ErrClosed) {
		t.Fatal("连接被关不算超时")
	}
}

// 固定端口被占用、客户端换了端口时：50010-50013 仍排在最前，其后跟着扫描段，
// 保证「老端口」和「可能的新端口」之间不会隔着几十个内部服务端口。
func TestBridgeTargetsOrderAndSweep(t *testing.T) {
	targets := bridgeTargets(wwLoginSettings{
		HTTPSPorts: []int{50010, 50011, 50012},
		HTTPPorts:  []int{50000, 50001, 50002},
	})
	pos := func(port int, mode bridgeMode) int {
		for i, tg := range targets {
			if tg.scheme == "https" && tg.port == port && tg.mode == mode {
				return i
			}
		}
		return -1
	}
	for _, port := range []int{50010, 50011, 50012, 50013, 50014, 50019} {
		if pos(port, bridgeChromeH2) < 0 {
			t.Fatalf("扫描列表里缺端口 %d", port)
		}
	}
	if !(pos(50013, bridgeChromeH2) < pos(50014, bridgeChromeH2)) {
		t.Fatal("扫描段应当排在 50013 之后")
	}
	sawHTTP := false
	for _, tg := range targets {
		if tg.scheme == "http" && tg.port == 50000 {
			sawHTTP = true
		}
	}
	if !sawHTTP {
		t.Fatal("http 端口族没有被列入候选")
	}
}

// 页面要有两个入口，且浏览器入口只在允许兜底时出现。
func TestWeComStaticHTMLEntries(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4e, 0x47}
	local := wecomStaticHTML("标题", "说明", png, true, false)
	if !strings.Contains(local, `id="local"`) {
		t.Fatal("缺少本地认证入口")
	}
	if strings.Contains(local, `id="browser"`) {
		t.Fatal("没有浏览器兜底时不该出现浏览器入口")
	}
	both := wecomStaticHTML("标题", "说明", png, true, true)
	if !strings.Contains(both, `id="browser"`) {
		t.Fatal("缺少浏览器兜底入口")
	}
	if !strings.Contains(both, "location.hash='browser-'") {
		t.Fatal("浏览器入口要写自己的 hash 前缀")
	}
}
