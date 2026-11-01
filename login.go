package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
)

var errLoginCanceled = errors.New("已取消扫码登录")

// diagLogin turns on verbose logging of the full login URL and the WeCom
// bridge replies, to work out the desktop quick-login payload.
const diagLogin = true

// wecomClickContinueScript clicks the "继续在浏览器中登录访问" control on
// WeCom's post-authorization page, which otherwise waits for a click and
// never redirects to the aTrust callback. It clicks at most one element and
// does no scanning beyond a small fixed set of selectors, so it is cheap.
const wecomClickContinueScript = `(function () {
  try {
    var wants = ["继续在浏览器中登录", "在浏览器中登录", "继续在浏览器"];
    var els = document.querySelectorAll("a,button,span,div");
    for (var i = 0; i < els.length; i++) {
      var t = (els[i].textContent || "").trim();
      if (!t || t.length > 30) continue;
      for (var j = 0; j < wants.length; j++) {
        if (t.indexOf(wants[j]) >= 0) { els[i].click(); return "clicked"; }
      }
    }
  } catch (e) {}
  return "none";
})()`

type loginResult struct {
	callback string
	err      error
}

// externalLogin shows the identity provider's login page in a window of its
// own, so that the user can scan the WeCom QR code the official client
// shows. It returns the https callback URL the provider redirects to, which
// ZJU-Connect sends on to the aTrust server.
//
// Only one such window is open at a time: a second access point waits for
// the first, so that "login all" with several QR points does not stack
// windows.
func (a *app) externalLogin(ctx context.Context, pointName, server, loginURL string) (string, error) {
	if strings.TrimSpace(loginURL) == "" {
		return "", errors.New("服务器没有给出扫码登录地址")
	}
	if a.win == nil {
		return "", errors.New("主窗口还没有打开")
	}
	if a.loginSem == nil {
		a.loginSem = make(chan struct{}, 1)
	}
	if a.bus != nil {
		a.bus.Add("app", fmt.Sprintf("[%s] 打开登录页 %s", pointName, loginPageForLog(loginURL)))
		if diagLogin {
			a.bus.Add("diag", fmt.Sprintf("[%s] FULL登录URL %s", pointName, loginURL))
		}
	}
	select {
	case a.loginSem <- struct{}{}:
		defer func() { <-a.loginSem }()
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// A child context ties every background poller to this call: closing the
	// window (or returning) cancels them, so a closed window never leaves a
	// goroutine polling WeCom's endpoint.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// WeCom's official page in a WebView freezes the whole app on this
	// machine (a hard macOS "application not responding"), repeatedly. So
	// WeCom never loads that page: we show its QR image on a static local
	// page with no scripts and drive the login from a pure-Go poller.
	if isWWLoginURL(loginURL) {
		if callback, err, ok := a.wecomStaticQRLogin(ctx, pointName, server, loginURL); ok {
			return callback, err
		}
	}
	if isQyWechatLoginURL(loginURL) {
		if callback, err, ok := a.qywechatStaticQRLogin(ctx, pointName, server, loginURL); ok {
			return callback, err
		}
	}

	loginWin := mygo.NewWindow(mygo.WindowOptions{
		Title:           "登录 — " + pointName,
		Width:           760,
		Height:          760,
		MinWidth:        520,
		MinHeight:       520,
		URL:             "about:blank",
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
	})
	if loginWin.IsDestroyed() {
		return "", errors.New("打不开扫码登录窗口")
	}
	page := loginWin.Page()
	if page == nil {
		loginWin.Close()
		return "", errors.New("扫码登录窗口没有网页")
	}

	var once sync.Once
	result := make(chan loginResult, 1)
	done := make(chan struct{})
	logLine := func(format string, args ...any) {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] ", pointName)+fmt.Sprintf(format, args...))
		}
	}
	// finish runs on the main thread, from a navigation callback or a
	// close.
	finish := func(callback string, err error) {
		logLine("登录窗口完成：callback=%v err=%v", callback != "", err)
		once.Do(func() {
			result <- loginResult{callback: callback, err: err}
			close(done)
			loginWin.Close()
		})
	}

	// The callback is caught before the page requests it, so that the
	// authorization code is not consumed by this window: the login's own
	// HTTP session then sends the same URL, as ZJU-Connect's CLI mode does
	// with a pasted callback.
	accept := func(rawURL string) bool {
		callback, ok := callbackFromURL(rawURL)
		if !ok {
			return false
		}
		if !strings.EqualFold(hostOf(callback), server) {
			// An identity provider may redirect through its own pages;
			// only the configured aTrust server's callback is ours.
			return false
		}
		finish(callback, nil)
		return true
	}
	page.OnWillNavigate(func(e *mygo.NavigateEvent) {
		logLine("登录页跳转 %s", loginPageForLog(e.URL))
		if accept(e.URL) {
			e.PreventDefault()
		}
	})
	// Some platforms commit a server redirect before the navigation policy
	// sees it; catch that too.
	page.OnDidNavigate(func(rawURL string) {
		logLine("登录页已到 %s", loginPageForLog(rawURL))
		accept(rawURL)
	})
	page.OnDidFailLoad(func(err *mygo.LoadError) {
		logLine("登录页加载失败：%s", err.Description)
	})
	page.OnPageTitleUpdated(func(e *mygo.TitleEvent) {
		logLine("登录页标题：%s", e.Title)
		// Keep our own title, which shows the scan/waiting state.
		e.PreventDefault()
	})
	// A few providers open the callback with window.open instead of
	// navigating the page; capture that too, and refuse unrelated popups.
	page.SetWindowOpenHandler(func(req mygo.WindowOpenRequest) *mygo.WindowOptions {
		logLine("登录页请求新窗口 %s", loginPageForLog(req.URL))
		if accept(req.URL) {
			return nil
		}
		// "Continue in the browser" and similar links open the next step in
		// a popup, which a window-less handler would deny, leaving the login
		// stuck. Load it in this window instead.
		if u, err := url.Parse(req.URL); err == nil &&
			(u.Scheme == "https" || u.Scheme == "http") {
			target := req.URL
			// Loading a page from inside the policy callback would
			// re-enter the WebView; do it on a later turn of the loop.
			go func() {
				time.Sleep(50 * time.Millisecond)
				if err := page.LoadURL(target); err != nil {
					logLine("登录页新窗口加载失败：%v", err)
				}
			}()
		}
		return nil
	})

	loginWin.OnClose(func(e *mygo.CloseEvent) {
		logLine("登录窗口被关闭")
		cancel()
		once.Do(func() {
			result <- loginResult{err: errLoginCanceled}
		})
	})

	if err := page.LoadURL(loginURL); err != nil {
		finish("", fmt.Errorf("打开登录页失败：%w", err))
	}
	loginWin.Show()
	loginWin.Focus()

	select {
	case r := <-result:
		return r.callback, r.err
	case <-time.After(3 * time.Minute):
		finish("", errors.New("登录超时，请重试"))
		return "", errors.New("登录超时，请重试")
	case <-ctx.Done():
		finish("", ctx.Err())
		return "", ctx.Err()
	}
}

// loginPageForLog keeps the origin and path of a login URL, dropping the
// query, which holds the provider's state.
func loginPageForLog(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// callbackFromURL reports whether rawURL is the aTrust page an identity
// provider redirects to after a successful external login, and returns it.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func callbackFromURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	path := strings.TrimSuffix(u.Path, "/")
	switch path {
	case "/passport/v1/auth/httpsOauth2":
		if u.Query().Get("code") == "" {
			return "", false
		}
	case "/passport/v1/auth/qywechat":
		if u.Query().Get("code") == "" && u.Query().Get("auth_code") == "" {
			return "", false
		}
	case "/passport/v1/auth/cas":
		if u.Query().Get("ticket") == "" {
			return "", false
		}
	default:
		return "", false
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", false
	}
	return rawURL, true
}

type qyWechatSettings struct {
	Key            string `json:"key"`
	AppID          string `json:"appid"`
	RedirectURI    string `json:"redirect_uri"`
	State          string `json:"state"`
	CodeType       int    `json:"code_type"`
	QRURL          string `json:"qrUrl"`
	LongPollGetURL string `json:"longPollGetUrl"`
}

type qyWechatPoll struct {
	Status      string `json:"status"`
	AuthCode    string `json:"auth_code"`
	RedirectURI string `json:"redirect_uri"`
}

// pollQyWechatQR is the fallback for a QR page that does not navigate after
// the scan is confirmed. It only reads the QR status; it never logs in by
// itself.
func (a *app) pollQyWechatQR(ctx context.Context, page *mygo.Page, done <-chan struct{}, pointName, server string, finish func(string, error), logLine func(string, ...any)) {
	var settings qyWechatSettings
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		default:
		}
		raw, err := page.Eval("JSON.stringify(window.settings)")
		if err == nil {
			if s, ok := raw.(string); ok && s != "" {
				_ = json.Unmarshal([]byte(s), &settings)
			}
		}
		if settings.Key != "" {
			break
		}
		if time.Now().After(deadline) {
			logLine("读不到二维码轮询参数，继续等待页面回调")
			return
		}
		time.Sleep(300 * time.Millisecond)
	}

	logLine("开始轮询二维码状态")
	poll, err := pollQyWechatStatus(ctx, settings, done, func(status string) {
		logLine("扫码状态：%s", status)
	})
	if err != nil {
		if errors.Is(err, errQRExpired) {
			logLine("二维码已过期，请在窗口里刷新")
		}
		return
	}
	redirect := poll.RedirectURI
	if redirect == "" {
		redirect = settings.RedirectURI
	}
	callback, err := qyWechatCallback(redirect, settings, poll.AuthCode)
	if err != nil || !callbackFromURLAllowed(callback, server) {
		logLine("二维码已确认，但回调地址不完整")
		return
	}
	logLine("手机已确认，收到扫码回调")
	finish(callback, nil)
}

var errQRExpired = errors.New("二维码已过期")

// pollQyWechatStatus polls WeCom's QR status endpoint until the phone
// confirms, the QR expires, or ctx ends. It calls onStatus when the status
// changes (except for the final success).
func pollQyWechatStatus(ctx context.Context, settings qyWechatSettings, done <-chan struct{}, onStatus func(string)) (qyWechatPoll, error) {
	endpoint := "https://open.work.weixin.qq.com/wwopen/sso/l/qrConnect"
	if settings.LongPollGetURL != "" {
		base, _ := url.Parse("https://open.work.weixin.qq.com")
		rel, err := url.Parse(settings.LongPollGetURL)
		if err == nil {
			endpoint = base.ResolveReference(rel).String()
		}
	}
	client := &http.Client{Timeout: 15 * time.Second}
	lastStatus := ""
	for {
		select {
		case <-done:
			return qyWechatPoll{}, context.Canceled
		case <-ctx.Done():
			return qyWechatPoll{}, ctx.Err()
		default:
		}
		q := url.Values{
			"key":          {settings.Key},
			"redirect_uri": {settings.RedirectURI},
			"appid":        {settings.AppID},
			"lastStatus":   {lastStatus},
			"callback":     {"jsonpCallback"},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+q.Encode(), nil)
		if err != nil {
			return qyWechatPoll{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			select {
			case <-done:
				return qyWechatPoll{}, context.Canceled
			case <-ctx.Done():
				return qyWechatPoll{}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		poll, err := parseQyWechatPoll(body)
		if err != nil {
			select {
			case <-done:
				return qyWechatPoll{}, context.Canceled
			case <-ctx.Done():
				return qyWechatPoll{}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if poll.Status != lastStatus {
			lastStatus = poll.Status
			if poll.Status != "QRCODE_SCAN_SUCC" && onStatus != nil {
				onStatus(poll.Status)
			}
		}
		switch poll.Status {
		case "QRCODE_SCAN_SUCC":
			return poll, nil
		case "QRCODE_SCAN_ERR":
			return qyWechatPoll{}, errQRExpired
		}
		select {
		case <-done:
			return qyWechatPoll{}, context.Canceled
		case <-ctx.Done():
			return qyWechatPoll{}, ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
	}
}

func parseQyWechatPoll(body []byte) (qyWechatPoll, error) {
	s := strings.TrimSpace(string(body))
	start := strings.Index(s, "(")
	end := strings.LastIndex(s, ")")
	if start >= 0 && end > start {
		s = s[start+1 : end]
	}
	var poll qyWechatPoll
	if err := json.Unmarshal([]byte(s), &poll); err != nil {
		return qyWechatPoll{}, err
	}
	return poll, nil
}

func qyWechatCallback(redirect string, settings qyWechatSettings, authCode string) (string, error) {
	if redirect == "" || authCode == "" {
		return "", errors.New("扫码回调缺少 code 或 redirect_uri")
	}
	u, err := url.Parse(strings.ReplaceAll(redirect, "&amp;", "&"))
	if err != nil {
		return "", err
	}
	q := u.Query()
	if settings.CodeType == 1 {
		q.Set("auth_code", authCode)
	} else {
		q.Set("code", authCode)
	}
	if settings.State != "" {
		q.Set("state", settings.State)
	}
	if settings.AppID != "" {
		q.Set("appid", settings.AppID)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func callbackFromURLAllowed(rawURL, server string) bool {
	if _, ok := callbackFromURL(rawURL); !ok {
		return false
	}
	return strings.EqualFold(hostOf(rawURL), server)
}
