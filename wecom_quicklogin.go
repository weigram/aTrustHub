package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// bridgeHost is the name the desktop client's certificate is issued for. The
// bridge only listens on the loopback interface, so the connection is dialled
// by address and the name is carried in SNI and the Host header.
const bridgeHost = "localhost.work.weixin.qq.com"

// bridgeUserAgent is a current desktop Chrome agent. The bridge expects a
// browser; a client that announces itself as something else is not answered.
const bridgeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// scenePCLogin is the scene the web login page sends for a desktop confirm.
const scenePCLogin = 1

// wwLoginSettings is what WeCom's web login page carries in __NUXT__: the
// keys of its own login state, the local ports of a running desktop client
// and the QR fallback.
type wwLoginSettings struct {
	WebKey      string `json:"web_key"`
	ClientKey   string `json:"client_key"`
	AppID       string `json:"appid"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	QRURL       string `json:"qrUrl"`
	// HTTPSPorts and HTTPPorts are the local bridge ports of a running
	// desktop client, from the page's pc_https_port / pc_http_port lists.
	HTTPSPorts []int
	HTTPPorts  []int
}

// isWWLoginURL reports whether loginURL is WeCom's web login page, whose
// whole flow can run without a web view.
func isWWLoginURL(loginURL string) bool {
	u, err := url.Parse(loginURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), "login.work.weixin.qq.com")
}

var (
	wwKeyPattern   = regexp.MustCompile(`"web_key":"([0-9a-f]+)"`)
	wwClientRe     = regexp.MustCompile(`"client_key":"([0-9a-f]+)"`)
	wwRedirectRe   = regexp.MustCompile(`"redirect_uri":"((?:[^"\\]|\\.)*)"`)
	wwStateRe      = regexp.MustCompile(`"state":"((?:[^"\\]|\\.)*)"`)
	wwQRURLRe      = regexp.MustCompile(`"qrUrl":"((?:[^"\\]|\\.)*)"`)
	wwHTTPSPortRe  = regexp.MustCompile(`"pc_https_port":\[([0-9,\s]+)\]`)
	wwHTTPPortList = regexp.MustCompile(`"pc_http_port":\[([0-9,\s]+)\]`)
)

func unescapeJSONString(s string) string {
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err == nil {
		return out
	}
	return s
}

// fetchWWLoginSettings loads WeCom's web login page and pulls the login keys
// out of its embedded state. No browser is involved.
func fetchWWLoginSettings(ctx context.Context, loginURL string) (wwLoginSettings, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return wwLoginSettings{}, err
	}
	req.Header.Set("User-Agent", bridgeUserAgent)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return wwLoginSettings{}, err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	_ = resp.Body.Close()
	s := wwLoginSettings{}
	if m := wwKeyPattern.FindSubmatch(page); m != nil {
		s.WebKey = string(m[1])
	}
	if m := wwClientRe.FindSubmatch(page); m != nil {
		s.ClientKey = string(m[1])
	}
	if m := wwRedirectRe.FindSubmatch(page); m != nil {
		s.RedirectURI = unescapeJSONString(string(m[1]))
	}
	if m := wwStateRe.FindSubmatch(page); m != nil {
		s.State = unescapeJSONString(string(m[1]))
	}
	if m := wwQRURLRe.FindSubmatch(page); m != nil {
		s.QRURL = unescapeJSONString(string(m[1]))
	}
	if m := wwHTTPSPortRe.FindSubmatch(page); m != nil {
		s.HTTPSPorts = parsePortList(m)
	}
	if m := wwHTTPPortList.FindSubmatch(page); m != nil {
		s.HTTPPorts = parsePortList(m)
	}
	if s.WebKey == "" || s.RedirectURI == "" {
		return wwLoginSettings{}, errors.New("网页登录参数不完整")
	}
	return s, nil
}

// wecomLogf writes a diagnostic line about the desktop quick-login bridge.
func wecomLogf(format string, args ...any) {
	if wecomLogHook != nil {
		wecomLogHook(fmt.Sprintf(format, args...))
	}
}

// wecomLogHook is set by the app so bridge diagnostics land in its log.
var wecomLogHook func(string)

// bridgeMode is how a bridge connection presents itself.
//
// The desktop client does not answer every TLS client: on Windows it drops the
// handshake of a client that offers no ALPN or that looks unlike a browser,
// while a Chromium page on the same port is served normally. So the same port
// is tried with a few different client hellos, cheapest first.
type bridgeMode int

const (
	// bridgePlainTLS is Go's own TLS client speaking HTTP/1.1. Some clients
	// (macOS) accept it: it is the shipped behaviour and stays first.
	bridgePlainTLS bridgeMode = iota
	// bridgeChromeH2 sends a Chrome client hello and speaks HTTP/2.
	bridgeChromeH2
	// bridgeChromeH1 sends a Chrome client hello and speaks HTTP/1.1.
	bridgeChromeH1
	// bridgeGoH2 is Go's TLS client with h2 offered, in case only the
	// missing ALPN is what the client objects to.
	bridgeGoH2
)

func (m bridgeMode) String() string {
	switch m {
	case bridgeChromeH2:
		return "chrome-h2"
	case bridgeChromeH1:
		return "chrome-h1"
	case bridgeGoH2:
		return "go-h2"
	default:
		return "plain"
	}
}

// bridgeTarget is one way to reach the desktop bridge.
type bridgeTarget struct {
	scheme string // "https" or "http"
	port   int
	mode   bridgeMode
}

func (t bridgeTarget) ok() bool { return t.port > 0 }

func (t bridgeTarget) String() string {
	if t.scheme == "http" {
		return fmt.Sprintf("http:%d", t.port)
	}
	return fmt.Sprintf("https:%d/%s", t.port, t.mode)
}

// bridgeClient talks to the desktop client's local bridge. It remembers the
// target that answered and the cookies the bridge handed out, so the confirm
// request that follows the probe is part of the same session.
type bridgeClient struct {
	mu      sync.Mutex
	target  bridgeTarget
	cookies []*http.Cookie
}

func (c *bridgeClient) setTarget(t bridgeTarget) {
	c.mu.Lock()
	c.target = t
	c.mu.Unlock()
}

func (c *bridgeClient) currentTarget() bridgeTarget {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.target
}

func (c *bridgeClient) hasTarget() bool { return c.currentTarget().ok() }

// rememberCookies keeps what the bridge set, so later requests carry it.
func (c *bridgeClient) rememberCookies(resp *http.Response) {
	if resp == nil {
		return
	}
	got := resp.Cookies()
	if len(got) == 0 {
		return
	}
	c.mu.Lock()
	c.cookies = append(c.cookies, got...)
	c.mu.Unlock()
}

func (c *bridgeClient) cookieSnapshot() []*http.Cookie {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*http.Cookie(nil), c.cookies...)
}

// bridgeProbe is the result of looking for a logged-in desktop client.
type bridgeProbe struct {
	target    bridgeTarget
	reachable bool
	loggedIn  bool
	// reject is the bridge's own reason when it answered but refused the
	// request, as it does for a Referer it does not accept.
	reject       string
	rejectTarget bridgeTarget
	errors       []string
}

// summary is the short reason shown when no client was found.
func (p bridgeProbe) summary() string {
	if len(p.errors) == 0 {
		return "没有可用的本地端口"
	}
	const max = 3
	shown := p.errors
	if len(shown) > max {
		shown = shown[:max]
	}
	out := strings.Join(shown, "；")
	if len(p.errors) > max {
		out += fmt.Sprintf(" 等 %d 个错误", len(p.errors))
	}
	return out
}

// bridgeTargets lists the endpoints worth trying.
//
// The desktop client prefers a few fixed ports but moves to a free one when
// they are taken, and that choice is made at every start, so the ports are
// asked for again on every click (wecomDesktopPorts) instead of being cached:
// a port that was the bridge a minute ago may belong to something else now.
// Ports the client process actually holds go first, then the ones the login
// page named, then the well-known ones.
func bridgeTargets(s wwLoginSettings) []bridgeTarget {
	discovered := orderDiscovered(dedupePorts(wecomDesktopPorts(nil)))

	// Last resort: a short sweep around the well-known ports. It covers a
	// client that moved to a free port which discovery could not attribute to
	// it — a renamed process, or a netstat column that changed with a Windows
	// update. Closed ports cost one refused dial each, so the sweep is cheap
	// next to missing the bridge entirely.
	httpsPorts := dedupePorts(append(append(append(append([]int{},
		discovered...), s.HTTPSPorts...), 50010, 50011, 50012, 50013),
		sweepPorts(50014, 50019)...))
	// A port the client picked for itself may be plain HTTP: the page tries
	// both families, so a port found by discovery is tried both ways too.
	httpPorts := dedupePorts(append(append(append([]int{},
		discovered...), s.HTTPPorts...), 50000, 50001, 50002))

	out := make([]bridgeTarget, 0, len(httpsPorts)*4+len(httpPorts))
	for _, port := range httpsPorts {
		for _, mode := range []bridgeMode{bridgePlainTLS, bridgeChromeH2, bridgeChromeH1, bridgeGoH2} {
			out = append(out, bridgeTarget{scheme: "https", port: port, mode: mode})
		}
	}
	for _, port := range httpPorts {
		out = append(out, bridgeTarget{scheme: "http", port: port})
	}
	return out
}

// sweepPorts is the inclusive range tried after the named ports.
func sweepPorts(from, to int) []int {
	out := make([]int, 0, to-from+1)
	for p := from; p <= to; p++ {
		out = append(out, p)
	}
	return out
}

func dedupePorts(ports []int) []int {
	seen := make(map[int]bool, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// probe finds a bridge endpoint that answers. It stops at the first endpoint
// that reports a logged-in client; an endpoint that answers without one is
// remembered so the caller can say "client not logged in" instead of
// "client not found".
func (c *bridgeClient) probe(ctx context.Context, targets []bridgeTarget, referer, redirectURI string) bridgeProbe {
	body := map[string]any{"redirect_uri": redirectURI, "scene": scenePCLogin}
	res := bridgeProbe{}
	open := map[int]bool{}
	// A port the client no longer holds may accept the connection and then
	// stay silent; when that happens the other client hellos on the same port
	// are pointless, so they are skipped instead of costing a timeout each.
	mute := map[int]bool{}
	for _, t := range targets {
		if ctx.Err() != nil {
			res.errors = append(res.errors, "探测超时")
			break
		}
		if mute[t.port] {
			continue
		}
		// One dial decides whether the port is worth four handshakes.
		if state, ok := open[t.port]; ok && !state {
			continue
		} else if !ok {
			state = bridgePortOpen(ctx, t.port)
			open[t.port] = state
			if !state {
				continue
			}
		}
		reply, err := c.do(ctx, t, "/checkLoginState", referer, body)
		if err != nil {
			res.errors = append(res.errors, fmt.Sprintf("%s: %s", t, shortError(err)))
			if bridgeTimedOut(err) {
				mute[t.port] = true
			}
			continue
		}
		// A 403 is a refused request, not a client that is merely logged
		// out; the bridge's own reason is more useful than a guess.
		if reason := bridgeRejectReason(reply); reason != "" {
			if res.reject == "" {
				res.reject = reason
				res.rejectTarget = t
			}
			continue
		}
		if !res.reachable {
			res.reachable = true
			res.target = t
		}
		if loginStateOf(reply) {
			c.setTarget(t)
			res.target = t
			res.loggedIn = true
			return res
		}
	}
	wecomLogf("企业微信本地桥探测结束：%d 个目标，可用=%v，已登录=%v", len(targets), res.reachable, res.loggedIn)
	return res
}

// bind asks the desktop client to show its confirmation prompt, the same call
// the login page's quick-login panel makes.
func (c *bridgeClient) bind(ctx context.Context, referer, clientKey string) (map[string]any, error) {
	t := c.currentTarget()
	if !t.ok() {
		return nil, errors.New("还没有找到电脑版企业微信")
	}
	out, err := c.do(ctx, t, "/confirmLogin", referer, map[string]any{
		"scene":   scenePCLogin,
		"web_key": clientKey,
	})
	if err != nil {
		return nil, err
	}
	if data, ok := out["data"].(map[string]any); ok {
		if result, ok := data["result"].(map[string]any); ok {
			if code, ok := result["errCode"].(float64); ok && code != 0 {
				return out, fmt.Errorf("桌面端返回错误 %.0f", code)
			}
		}
	}
	return out, nil
}

// do performs one request against one target.
func (c *bridgeClient) do(ctx context.Context, t bridgeTarget, path, referer string, body map[string]any) (map[string]any, error) {
	// Loopback answers in microseconds; a second is already generous. Keeping
	// it short matters because a port that another program now holds may
	// accept a connection and then sit there.
	attempt, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	conn, err := dialBridge(attempt, t.port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := attempt.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req, raw, err := newBridgeRequest(t, path, referer, body, c.cookieSnapshot())
	if err != nil {
		return nil, err
	}
	if t.scheme == "http" {
		return bridgeRoundTripH1(conn, req, raw, c)
	}
	tlsConn, err := wrapBridgeTLS(attempt, conn, t.mode)
	if err != nil {
		return nil, err
	}
	if t.mode == bridgeChromeH2 || t.mode == bridgeGoH2 {
		return bridgeRoundTripH2(tlsConn, req, c)
	}
	return bridgeRoundTripH1(tlsConn, req, raw, c)
}

// newBridgeRequest builds the request the login page would send. The bridge
// checks where the request came from, so the headers a page would carry are
// set explicitly.
func newBridgeRequest(t bridgeTarget, path, referer string, body map[string]any, cookies []*http.Cookie) (*http.Request, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	// The page reaches the https bridge by name and the http one by address.
	host := net.JoinHostPort(bridgeHost, strconv.Itoa(t.port))
	if t.scheme == "http" {
		host = net.JoinHostPort("127.0.0.1", strconv.Itoa(t.port))
	}
	req, err := http.NewRequest(http.MethodPost,
		(&url.URL{Scheme: t.scheme, Host: host, Path: path}).String(), bytes.NewReader(raw))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", bridgeUserAgent)
	req.Header.Set("Referer", referer)
	if pu, err := url.Parse(referer); err == nil && pu.Scheme != "" && pu.Host != "" {
		req.Header.Set("Origin", pu.Scheme+"://"+pu.Host)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return req, raw, nil
}

// dialBridge connects to the loopback address, IPv4 first. Some client builds
// only bind the IPv6 loopback on Windows.
func dialBridge(ctx context.Context, port int) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		return conn, nil
	}
	if conn6, err6 := dialer.DialContext(ctx, "tcp", net.JoinHostPort("::1", strconv.Itoa(port))); err6 == nil {
		return conn6, nil
	}
	return nil, err
}

// bridgePortOpen reports whether anything accepts a connection on the port.
func bridgePortOpen(ctx context.Context, port int) bool {
	probe, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	for _, addr := range []string{"127.0.0.1", "::1"} {
		conn, err := (&net.Dialer{}).DialContext(probe, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}

// wrapBridgeTLS wraps conn the way the selected mode says.
func wrapBridgeTLS(ctx context.Context, conn net.Conn, mode bridgeMode) (net.Conn, error) {
	switch mode {
	case bridgeChromeH2, bridgeChromeH1:
		next := []string{"h2"}
		if mode == bridgeChromeH1 {
			next = []string{"http/1.1"}
		}
		// A Chrome client hello; the local bridge answers it, while it drops
		// the handshake of a client that does not offer ALPN at all.
		u := utls.UClient(conn, &utls.Config{
			ServerName:         bridgeHost,
			InsecureSkipVerify: true,
			NextProtos:         next,
		}, utls.HelloChrome_Auto)
		if err := u.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return u, nil
	case bridgeGoH2:
		tc := tls.Client(conn, &tls.Config{
			ServerName:         bridgeHost,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tc, nil
	default:
		// Exactly what earlier builds used, which is what macOS needs.
		tc := tls.Client(conn, &tls.Config{
			ServerName:         bridgeHost,
			InsecureSkipVerify: true,
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return tc, nil
	}
}

// bridgeRoundTripH1 writes the request on conn and reads one response.
func bridgeRoundTripH1(conn net.Conn, req *http.Request, raw []byte, c *bridgeClient) (map[string]any, error) {
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.rememberCookies(resp)
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return decodeBridgeReply(b)
}

// bridgeRoundTripH2 speaks HTTP/2 on an already negotiated connection.
func bridgeRoundTripH2(conn net.Conn, req *http.Request, c *bridgeClient) (map[string]any, error) {
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.rememberCookies(resp)
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return decodeBridgeReply(b)
}

func decodeBridgeReply(b []byte) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("返回不是 JSON：%s", clip(string(b), 120))
	}
	return out, nil
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// shortError keeps a log line readable: dial and TLS errors repeat the address.
func shortError(err error) string {
	msg := err.Error()
	msg = strings.TrimPrefix(msg, "Post ")
	if len(msg) > 110 {
		msg = msg[:110] + "…"
	}
	return msg
}

// bridgeTimedOut reports whether the attempt failed by running out of time
// rather than by being refused. A refusal means "nothing there"; a timeout
// means "something is there but does not speak our language", and no other
// client hello is going to change that.
func bridgeTimedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// loginStateOf reads login_state, which the bridge sends as a number.
func loginStateOf(out map[string]any) bool {
	data, _ := out["data"].(map[string]any)
	if data == nil {
		return false
	}
	switch v := data["login_state"].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v == "1" || v == "true"
	}
	return false
}

// bridgeRejectReason returns why the bridge refused a request, if it did. The
// bridge answers
//
//	{"data":{"statusCode":403,"result":{"errCode":10050002,"errMsg":"referer verify fail"}}}
//
// when the request's origin is not one it accepts.
func bridgeRejectReason(out map[string]any) string {
	data, _ := out["data"].(map[string]any)
	if data == nil {
		return ""
	}
	result, _ := data["result"].(map[string]any)
	if code, ok := data["statusCode"].(float64); ok && code >= 400 {
		if msg, _ := result["errMsg"].(string); msg != "" {
			return fmt.Sprintf("%.0f %s", code, msg)
		}
		return fmt.Sprintf("HTTP %.0f", code)
	}
	if code, ok := result["errCode"].(float64); ok && code != 0 {
		msg, _ := result["errMsg"].(string)
		return strings.TrimSpace(fmt.Sprintf("%.0f %s", code, msg))
	}
	return ""
}

// wwStatus is one poll result of WeCom's server-side login status.
type wwStatus struct {
	Status      string `json:"status"`
	AuthCode    string `json:"auth_code"`
	RedirectURI string `json:"redirect_uri"`
}

// wecomStatusPoll asks WeCom's server for the current login status of webKey.
// The endpoint takes a form-encoded body and answers {data:{status,...}}.
func wecomStatusPoll(ctx context.Context, webKey, lastStatus, referer string) (wwStatus, error) {
	form := url.Values{"webKey": {webKey}, "lastStatus": {lastStatus}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.work.weixin.qq.com/wwlogin/monoApi/sso/login/getWebQrCodeStatus",
		strings.NewReader(form.Encode()))
	if err != nil {
		return wwStatus{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", bridgeUserAgent)
	req.Header.Set("Referer", referer)
	resp, err := (&http.Client{Timeout: 18 * time.Second}).Do(req)
	if err != nil {
		return wwStatus{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var wrap struct {
		Data wwStatus `json:"data"`
	}
	var st wwStatus
	if json.Unmarshal(b, &wrap) == nil {
		st = wrap.Data
	}
	return st, nil
}

// wecomConfirmQuick asks WeCom's server to finish the desktop quick login and
// return the authorization code. It succeeds once the user confirmed in the
// desktop client; earlier it answers 参数错误, which the caller treats as
// "not confirmed yet".
func wecomConfirmQuick(ctx context.Context, webKey, referer string) (string, error) {
	form := url.Values{"qrcode_key": {webKey}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.work.weixin.qq.com/wwlogin/monoApi/sso/login/confirmQuickLoginByKey",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", bridgeUserAgent)
	req.Header.Set("Referer", referer)
	resp, err := (&http.Client{Timeout: 18 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var wrap struct {
		Data struct {
			AuthCode string `json:"auth_code"`
			Redirect string `json:"redirect_uri"`
		} `json:"data"`
		AuthCode string `json:"auth_code"`
		Redirect string `json:"redirect_uri"`
	}
	_ = json.Unmarshal(b, &wrap)
	if wrap.Data.AuthCode != "" {
		return wrap.Data.AuthCode, nil
	}
	if wrap.AuthCode != "" {
		return wrap.AuthCode, nil
	}
	return "", errNotConfirmed
}

// errNotConfirmed means the server answered, but the login is not confirmed
// yet — the caller keeps waiting.
var errNotConfirmed = errors.New("尚未在企业微信中确认")

// pollWeComLogin polls WeCom's status endpoint until the code arrives, the QR
// expires, the window is closed, or ctx ends. Once the click handler found a
// desktop client, the confirmation request is re-sent periodically in case the
// first prompt was missed, so a stalled "PC_BIND" does not sit forever.
func (a *app) pollWeComLogin(ctx context.Context, pointName, server, loginURL string, settings wwLoginSettings, bridge *bridgeClient, logLine func(string, ...any)) (string, bool, error) {
	pollCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		callback string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		last := "QRCODE_SCAN_NEVER"
		start := time.Now()
		nextBind := time.Time{}
		for {
			select {
			case <-pollCtx.Done():
				return
			case <-ctx.Done():
				return
			case <-time.After(1500 * time.Millisecond):
			}
			st, err := wecomStatusPoll(pollCtx, settings.WebKey, last, loginURL)
			if err != nil || st.Status == "" {
				continue
			}
			if st.Status != last {
				last = st.Status
				logLine("企业微信登录状态：%s（%.0fs）", st.Status, time.Since(start).Seconds())
			}
			switch st.Status {
			case "QRCODE_SCAN_SUCC":
				code := st.AuthCode
				if code == "" {
					var err error
					code, err = wecomConfirmQuick(pollCtx, settings.WebKey, loginURL)
					if err != nil || code == "" {
						continue
					}
				}
				done <- result{callback: wwCallback(settings, code)}
				return
			case "QRCODE_SCAN_PC_BIND", "QRCODE_SCAN_ING":
				// The page often stops at "PC_BIND" and waits for a button
				// click instead of finishing on its own. Once the user has
				// authorized, the code is exchangable even without that click,
				// so try to exchange it here; "not confirmed" just means keep
				// waiting.
				if code, cerr := wecomConfirmQuick(pollCtx, settings.WebKey, loginURL); cerr == nil && code != "" {
					logLine("已在后台换到登录 code，关闭窗口")
					done <- result{callback: wwCallback(settings, code)}
					return
				}
				// A desktop client may be handling it: re-ask it to show its
				// prompt every few seconds in case the first was missed.
				if bridge != nil && st.Status == "QRCODE_SCAN_PC_BIND" && bridge.hasTarget() && time.Now().After(nextBind) {
					nextBind = time.Now().Add(4 * time.Second)
					go func() {
						if _, err := bridge.bind(pollCtx, loginURL, settings.ClientKey); err != nil {
							logLine("重新发送确认请求失败：%v", err)
						}
					}()
				}
			}
		}
	}()

	select {
	case r := <-done:
		return r.callback, true, r.err
	case <-ctx.Done():
		return "", true, ctx.Err()
	case <-time.After(3 * time.Minute):
		return "", true, errors.New("企业微信登录超时")
	}
}

// parsePortList turns a "50010,50011" capture into ports.
func parsePortList(m [][]byte) []int {
	if len(m) < 2 {
		return nil
	}
	var out []int
	for _, part := range strings.Split(string(m[1]), ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && p > 0 {
			out = append(out, p)
		}
	}
	return out
}

// wwCallback builds the aTrust callback URL from the WeCom authorization code.
func wwCallback(s wwLoginSettings, code string) string {
	u, err := url.Parse(s.RedirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("code", code)
	if s.State != "" {
		q.Set("state", s.State)
	}
	if s.AppID != "" {
		q.Set("appid", s.AppID)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
