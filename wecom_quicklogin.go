package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

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
	// HTTPSPorts are the local bridge ports of a running desktop client,
	// from the page's pc_https_port list.
	HTTPSPorts []int
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
	wwHTTPPortList = regexp.MustCompile(`"pc_http_port":\[([0-9,\s]+)\]`)
	wwHTTPSPortRe  = regexp.MustCompile(`"pc_https_port":\[([0-9,\s]+)\]`)
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
	req.Header.Set("User-Agent", "Mozilla/5.0")
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
	if s.WebKey == "" || s.RedirectURI == "" {
		return wwLoginSettings{}, errors.New("网页登录参数不完整")
	}
	return s, nil
}

// wecomLocalPost calls a WeCom desktop client's local bridge.
func wecomLocalPost(ctx context.Context, port int, path string, body any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://127.0.0.1:"+strconv.Itoa(port)+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 4 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil, fmt.Errorf("invalid response %d", resp.StatusCode)
	}
	return out, nil
}

// wecomBridge is the HTTP client for a WeCom desktop client's local bridge,
// which serves HTTPS on localhost.work.weixin.qq.com with its own certificate.
func wecomBridge() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost.work.weixin.qq.com"},
		},
	}
}

// wecomBridgePost posts JSON to the desktop client's local bridge. The
// bridge verifies the Referer of the login page.
func wecomBridgePost(ctx context.Context, port int, path, referer string, body map[string]any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://localhost.work.weixin.qq.com:"+strconv.Itoa(port)+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", referer)
	// The bridge checks these the way a browser would, so a request that
	// looks like it came from the login page is treated like one.
	if u, err := url.Parse(referer); err == nil && u.Scheme != "" && u.Host != "" {
		req.Header.Set("Origin", u.Scheme+"://"+u.Host)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Host = "localhost.work.weixin.qq.com"
	resp, err := wecomBridge().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out, nil
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

// wecomDesktopState reports whether a logged-in desktop WeCom answers on one
// of its local bridge ports, and returns that port. The ports come from the
// login page's pc_https_port list plus known fallbacks.
func wecomDesktopState(ctx context.Context, ports []int, referer, redirectURI string) (int, bool) {
	for _, port := range ports {
		ctxShort, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		out, err := wecomBridgePost(ctxShort, port, "/checkLoginState", referer, map[string]any{
			"redirect_uri": redirectURI,
			"scene":        1, // PC_LOGIN
		})
		cancel()
		if err != nil {
			continue
		}
		if loginStateOf(out) {
			return port, true
		}
	}
	return 0, false
}

// wecomBindWeCom asks the desktop client to show its confirmation prompt,
// the same call the login page's quick-login panel makes.
func wecomBindWeCom(ctx context.Context, port int, referer, clientKey string) error {
	out, err := wecomBridgePost(ctx, port, "/confirmLogin", referer, map[string]any{
		"scene":   1, // PC_LOGIN
		"web_key": clientKey,
	})
	if err != nil {
		return err
	}
	if data, ok := out["data"].(map[string]any); ok {
		if result, ok := data["result"].(map[string]any); ok {
			if code, _ := result["errCode"].(float64); code != 0 {
				return fmt.Errorf("桌面端返回错误 %.0f", code)
			}
		}
	}
	return nil
}

// wecomBindWeComVerbose is wecomBindWeCom with the raw bridge reply returned,
// for diagnostics. It never changes behavior.
func wecomBindWeComVerbose(ctx context.Context, port int, referer, clientKey string) (map[string]any, error) {
	return wecomBridgePost(ctx, port, "/confirmLogin", referer, map[string]any{
		"scene":   1, // PC_LOGIN
		"web_key": clientKey,
	})
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
	req.Header.Set("User-Agent", "Mozilla/5.0")
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
	req.Header.Set("User-Agent", "Mozilla/5.0")
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
// expires, the window is closed, or ctx ends. When a desktop client was found,
// it re-sends the confirmation request periodically in case the first prompt
// was missed, so a stalled "PC_BIND" does not sit forever.
func (a *app) pollWeComLogin(ctx context.Context, pointName, server, loginURL string, settings wwLoginSettings, desktop bool, port int, logLine func(string, ...any)) (string, bool, error) {
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
				if desktop && st.Status == "QRCODE_SCAN_PC_BIND" && time.Now().After(nextBind) {
					nextBind = time.Now().Add(4 * time.Second)
					go func() {
						if out, err := wecomBindWeComVerbose(pollCtx, port, loginURL, settings.ClientKey); err != nil {
							logLine("重新发送确认请求失败：%v", err)
						} else if data, ok := out["data"].(map[string]any); ok {
							if r, ok := data["result"].(map[string]any); ok {
								logLine("确认请求返回：%v", r["errCode"])
							}
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
