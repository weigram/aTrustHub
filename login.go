package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
func (a *app) externalLogin(ctx context.Context, pointName, server, loginURL string, inBrowser bool) (string, error) {
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

	if inBrowser {
		return a.browserLogin(ctx, pointName, server, loginURL)
	}

	loginWin := mygo.NewWindow(mygo.WindowOptions{
		Title:           "登录 — " + pointName,
		Width:           760,
		Height:          760,
		MinWidth:        520,
		MinHeight:       520,
		URL:             "about:blank",
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		// The identity provider of one deployment refuses the WebView's own
		// user agent as "too old". A current desktop browser's agent is what
		// the page expects; the request itself is unchanged.
		Page: mygo.PageOptions{
			UserAgent:     loginUserAgent,
			DevTools:      mygo.DevToolsEnabled,
			PreloadScript: devToolsShortcut,
		},
	})
	if loginWin.IsDestroyed() {
		return "", errors.New("打不开扫码登录窗口")
	}
	page := loginWin.Page()
	if page == nil {
		loginWin.Close()
		return "", errors.New("扫码登录窗口没有网页")
	}

	// fallbackURL is used once if the portal page cannot be shown at all.
	fallbackURL := ""
	// target holds the address the window should be showing, so a certificate
	// the user's server presents can be accepted and the page retried.
	var targetMu sync.Mutex
	target := loginURL
	currentTarget := func() string {
		targetMu.Lock()
		defer targetMu.Unlock()
		return target
	}
	setTarget := func(u string) {
		targetMu.Lock()
		target = u
		targetMu.Unlock()
	}
	var pasteMode atomic.Bool
	// acceptedCert is set once a certificate of this server was accepted, so a
	// later failure is not mistaken for "the WebView cannot use the
	// certificate" and does not switch away to the browser flow.
	var acceptedCert atomic.Bool
	// visited hosts the login reached: the access point, and the identity
	// provider it redirects to. A self-signed certificate is accepted only
	// for these, never for an arbitrary host.
	visited := &hostSet{hosts: map[string]bool{}}
	visited.add(server)
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

	// startPasteLogin opens the page in the system browser, where the
	// certificate can be accepted, and asks for the callback address it ends
	// on. It is the reliable path when the WebView refuses the certificate.
	startPasteLogin := func() {
		logLine("证书不被内置浏览器接受，改用系统浏览器登录")
		target := currentTarget()
		if err := mygo.Shell.OpenExternal(target); err != nil {
			logLine("打开浏览器失败：%v", err)
		}
		page.LoadHTML(pasteLoginHTML("需要你在浏览器里登录 — "+pointName,
			"这个服务器的证书浏览器内核不接受，已改用系统浏览器打开登录页。", target), "")
		go func() {
			ticker := time.NewTicker(700 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				raw, err := page.EvalContext(evalCtx,
					`(function(){var b=document.getElementById('cb');return b?b.value:'';})()`)
				cancel()
				if err != nil {
					continue
				}
				text, _ := raw.(string)
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				if callbackFromURLAllowed(text, server) {
					finish(text, nil)
					return
				}
				// Keep the typed text, but show why it was refused.
				quoted, _ := json.Marshal("地址不对：需要以 https://" + server + "/passport/v1/auth/ 开头的回调地址")
				evalCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
				_, _ = page.EvalContext(evalCtx2,
					`(function(){var e=document.getElementById('err');if(e){e.textContent=`+string(quoted)+`;}})()`)
				cancel2()
			}
		}()
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
	// A single sign-on that redirects several times does not always reach the
	// askProvider is the "logged in, get a fresh code" step: the access point
	// itself would answer with the portal, since this window already holds its
	// session, but the identity provider hands out a new ticket when asked
	// directly.
	var harvestOnce sync.Once
	askProvider := func() {
		harvestOnce.Do(func() {
			reportPageSession(page, logLine)
			target := loginURL
			if idp := identityProviderURL(ctx, loginURL, server); idp != "" {
				target = idp
				logLine("已登录，向身份提供方重新取一次票：%s", loginPageForLog(idp))
			} else {
				logLine("已登录，重新请求认证地址以取票")
			}
			go func() {
				time.Sleep(300 * time.Millisecond)
				if err := page.LoadURL(target); err != nil {
					logLine("重新取票失败：%v", err)
				}
			}()
		})
	}

	// A light poll, 2 s apart, watches only the page's own address. It is what
	// notices the debug buttons and a page that stopped moving; the login
	// itself is followed through the navigation callbacks below, because
	// querying a heavy single sign-on page often enough to matter freezes it.
	go func() {
		lastHref := ""
		lastChange := time.Now()
		idleLogged := false
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			raw, err := page.EvalContext(evalCtx, `(function(){ try { return location.href || ''; } catch (e) { return ''; } })()`)
			cancel()
			if err != nil {
				continue
			}
			href, _ := raw.(string)
			reportPageErrors(page, logLine)
			if strings.Contains(href, "#devtools") {
				page.OpenDevTools()
			}
			if strings.Contains(href, "#browser") && !pasteMode.Load() {
				pasteMode.Store(true)
				fallbackURL = ""
				logLine("按用户要求改用系统浏览器登录")
				startPasteLogin()
			}
			if href != lastHref {
				lastHref, lastChange, idleLogged = href, time.Now(), false
			} else if !idleLogged && time.Since(lastChange) > 45*time.Second {
				idleLogged = true
				logLine("登录页 45 秒没有变化，停在 %s", loginPageForLog(href))
			}
		}
	}()

	// aTrust appliances usually serve a self-signed certificate, which the
	// WebView refuses by default: the login page then stays blank. Accept it
	// only for the server this access point was configured with, and log the
	// fingerprint so the certificate in use is on record.
	var reloadOnce sync.Once
	page.SetCertificateErrorHandler(func(e mygo.CertificateError) bool {
		host := e.Host
		if host == "" {
			if u, err := url.Parse(e.URL); err == nil {
				host = u.Hostname()
			}
		}
		if !visited.has(host) {
			logLine("拒绝未访问主机的证书：%s（%s）", host, e.Error)
			return false
		}
		sum := sha256.Sum256(e.Certificate)
		logLine("接受 %s 的证书（%s，指纹 %x）", host, e.Error, sum[:8])
		acceptedCert.Store(true)
		// WebView2 fails the load before it asks, so the page has to be
		// loaded again once the certificate is allowed. WebKit accepts the
		// credential mid-load instead; reloading there would abort the very
		// load that is about to succeed.
		if runtime.GOOS == "windows" {
			reloadOnce.Do(func() {
				go func() {
					time.Sleep(300 * time.Millisecond)
					if pasteMode.Load() || !acceptedCert.Load() {
						return
					}
					if err := page.LoadURL(currentTarget()); err != nil {
						logLine("重新加载登录页失败：%v", err)
					}
				}()
			})
		}
		return true
	})
	activity := make(chan struct{}, 1)
	noteActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	page.OnWillNavigate(func(e *mygo.NavigateEvent) {
		noteActivity()
		visited.add(hostOf(e.URL))
		logLine("登录页跳转 %s", loginPageForLog(e.URL))
		if accept(e.URL) {
			e.PreventDefault()
		}
	})
	// Some platforms commit a server redirect before the navigation policy
	// sees it; catch that too.
	page.OnDidNavigate(func(rawURL string) {
		visited.add(hostOf(rawURL))
		logLine("登录页已到 %s", loginPageForLog(rawURL))
		if accept(rawURL) {
			return
		}
		if landedOnPortal(rawURL, server) {
			askProvider()
		}
	})
	page.OnDidFailLoad(func(err *mygo.LoadError) {
		logLine("登录页加载失败：%s（%s）", err.Description, loginPageForLog(err.URL))
		// A self-signed appliance certificate that the WebView refuses leaves
		// a blank window. Fall back to logging in with the system browser and
		// pasting the callback address, which is what the CLI client does.
		if !pasteMode.Load() && !acceptedCert.Load() && isCertificateFailure(err.Description) {
			pasteMode.Store(true)
			fallbackURL = ""
			startPasteLogin()
			return
		}
		// If the portal address itself does not load, fall back to the
		// identity provider's entry point, which is the shorter path anyway.
		if fallbackURL != "" {
			next := fallbackURL
			fallbackURL = ""
			logLine("改用认证地址 %s", loginPageForLog(next))
			setTarget(next)
			go func() {
				time.Sleep(200 * time.Millisecond)
				if err := page.LoadURL(next); err != nil {
					logLine("认证地址加载失败：%v", err)
				}
			}()
		}
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

	// A CAS/SSO server is opened at its portal address rather than at the
	// casLogin endpoint: the portal is the page the user recognises, and its
	// own login button walks through the identity provider and comes back to
	// /passport/v1/auth/cas, which is the callback this window waits for.
	startURL := loginURL
	if isCASLoginURL(loginURL) {
		if u, err := url.Parse(loginURL); err == nil && u.Host != "" {
			startURL = u.Scheme + "://" + u.Host + "/"
			fallbackURL = loginURL
		}
	}
	if startURL != loginURL {
		logLine("单点登录：先在 %s 登录，完成后自动返回", loginPageForLog(startURL))
	}
	setTarget(startURL)
	if err := page.LoadURL(startURL); err != nil {
		finish("", fmt.Errorf("打开登录页失败：%w", err))
	}
	loginWin.Show()
	loginWin.Focus()
	// The inspector is opened right away: the login page is where a broken
	// request has to be watched, and waiting for a click is too late.
	go func() {
		time.Sleep(700 * time.Millisecond)
		page.OpenDevTools()
	}()

	// A portal whose login never finishes inside the WebView would otherwise
	// wait forever: after two idle minutes, hand the page to the browser.
	go func() {
		const idle = 120 * time.Second
		timer := time.NewTimer(idle)
		defer timer.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-activity:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idle)
			case <-timer.C:
				if !pasteMode.Load() {
					logLine("登录页两分钟没有进展，改用系统浏览器登录")
					pasteMode.Store(true)
					fallbackURL = ""
					startPasteLogin()
				}
				return
			}
		}
	}()

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

// identityProviderURL asks the access point where it sends a login, which is
// the identity provider's own address. Loading that one again, with the
// provider's session already in the window, returns a fresh ticket.
func identityProviderURL(ctx context.Context, loginURL, server string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return ""
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	if strings.EqualFold(u.Hostname(), server) {
		// Still the access point itself: nothing to ask again.
		return ""
	}
	return loc
}

// devToolsShortcut makes F12 (and the usual chord) ask for the web inspector.
// The page itself cannot open it, so it leaves a marker the window watches for:
// the login pages are remote, and this keeps the shortcut working on all of
// them without touching their markup.
const devToolsShortcut = `(function(){
  try {
    if (!window.__hubErrors) {
      window.__hubErrors = [];
      window.addEventListener('error', function(e){
        window.__hubErrors.push('error: ' + (e && e.message ? e.message : 'unknown') +
          (e && e.filename ? ' @ ' + e.filename + ':' + e.lineno : ''));
      }, true);
      window.addEventListener('unhandledrejection', function(e){
        window.__hubErrors.push('rejection: ' + (e && e.reason ? String(e.reason) : 'unknown'));
      }, true);
    }
  } catch (e) {}

  var mark = function(tag){
    try { history.replaceState(null, '', '#' + tag); } catch (err) { location.hash = tag; }
  };
  var open = function(){ mark('devtools'); };
  var wants = function(e){ return e.key === 'F12' || (e.key === 'i' && (e.metaKey || e.ctrlKey) && e.shiftKey); };
  window.addEventListener('keydown', function(e){
    if (!wants(e)) return;
    e.preventDefault();
    open();
  }, true);
  // A visible way in: the login page cannot be clicked through by keyboard
  // focus alone, and this works on every page the login shows.
  var add = function(){
    if (document.getElementById('__hub_debug')) return;
    var b = document.createElement('button');
    b.id = '__hub_debug';
    b.textContent = '调试';
    b.title = '打开开发者工具（也可按 F12）';
    b.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:2147483647;' +
      'font:12px -apple-system,system-ui,sans-serif;padding:5px 10px;border-radius:8px;' +
      'border:1px solid rgba(0,0,0,.2);background:rgba(255,255,255,.92);color:#333;cursor:pointer;' +
      'box-shadow:0 1px 4px rgba(0,0,0,.18)';
    b.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); open(); });
    var c = document.createElement('button');
    c.id = '__hub_browser';
    c.textContent = '用浏览器登录';
    c.title = '在系统浏览器里登录，再把回调地址粘回来';
    c.style.cssText = b.style.cssText + ';right:64px';
    c.addEventListener('click', function(e){ e.preventDefault(); e.stopPropagation(); mark('browser'); });
    var host = document.body || document.documentElement;
    host.appendChild(b);
    host.appendChild(c);
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', add);
  } else {
    add();
  }
})()`

// pasteProbe returns the page address and what was typed into the callback
// field, so one poll covers both the shortcut and the address.
const pasteProbe = `(function(){
  var b = document.getElementById('cb');
  return JSON.stringify([location.href, b ? b.value : '']);
})()`

// parsePasteProbe reads what pasteProbe returned.
func parsePasteProbe(raw any) (href, text string) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", ""
	}
	var parts []string
	if err := json.Unmarshal([]byte(s), &parts); err != nil || len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// reportPageErrors writes the page's own JavaScript errors to the app log,
// which is what a page that never renders usually leaves behind.
var pageErrorsReported int

func reportPageErrors(page *mygo.Page, logLine func(string, ...any)) {
	if page == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := page.EvalContext(ctx, `(function(){ try { return JSON.stringify((window.__hubErrors||[]).slice(-6)); } catch (e) { return '[]'; } })()`)
	if err != nil {
		return
	}
	text, _ := raw.(string)
	if text == "" || text == "[]" || len(text) <= pageErrorsReported {
		return
	}
	pageErrorsReported = len(text)
	logLine("页面脚本错误：%s", text)
}

// reportPageSession logs what the logged-in page keeps client side. A portal
// that finishes the login with an XHR keeps the session in cookies, and only
// what JavaScript can read can be taken over by the tunnel.
func reportPageSession(page *mygo.Page, logLine func(string, ...any)) {
	if page == nil {
		return
	}
	const probe = `(function(){
  var out = {cookie: '', ls: [], ss: []};
  try { out.cookie = document.cookie || ''; } catch (e) {}
  try { for (var i = 0; i < localStorage.length; i++) { var k = localStorage.key(i); out.ls.push(k + '=' + (localStorage.getItem(k) || '').length); } } catch (e) {}
  try { for (var i = 0; i < sessionStorage.length; i++) { var k = sessionStorage.key(i); out.ss.push(k + '=' + (sessionStorage.getItem(k) || '').length); } } catch (e) {}
  return JSON.stringify(out);
})()`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := page.EvalContext(ctx, probe)
	if err != nil {
		logLine("读取页面会话失败：%v", err)
		return
	}
	text, _ := raw.(string)
	var got struct {
		Cookie string   `json:"cookie"`
		LS     []string `json:"ls"`
		SS     []string `json:"ss"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		logLine("页面会话无法解析：%v", err)
		return
	}
	names := make([]string, 0, 8)
	for _, part := range strings.Split(got.Cookie, ";") {
		if kv := strings.SplitN(strings.TrimSpace(part), "=", 2); len(kv) == 2 && kv[0] != "" {
			names = append(names, fmt.Sprintf("%s(%d)", kv[0], len(kv[1])))
		}
	}
	logLine("页面会话：cookie=[%s] localStorage=[%s] sessionStorage=[%s]",
		strings.Join(names, " "), strings.Join(got.LS, " "), strings.Join(got.SS, " "))
}

// hostSet is the set of hosts one login window has reached.
type hostSet struct {
	mu    sync.Mutex
	hosts map[string]bool
}

func (h *hostSet) add(host string) {
	if host == "" {
		return
	}
	h.mu.Lock()
	h.hosts[strings.ToLower(host)] = true
	h.mu.Unlock()
}

func (h *hostSet) has(host string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hosts[strings.ToLower(host)]
}

// landedOnPortal reports whether rawURL is a page of the aTrust server that is
// not the authentication callback, which means the login finished inside the
// window.
func landedOnPortal(rawURL, server string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return false
	}
	if !strings.EqualFold(u.Hostname(), server) {
		return false
	}
	path := strings.TrimSuffix(u.Path, "/")
	if strings.HasPrefix(path, "/passport/v1/auth") {
		return false
	}
	return path == "/portal" || strings.HasPrefix(path, "/portal/")
}

// loginUserAgent is the user agent the login window presents. Some aTrust
// portals refuse anything else as an outdated browser, so it matches a current
// desktop browser of the platform the app runs on.
var loginUserAgent = func() string {
	platform := "X11; Linux x86_64"
	switch runtime.GOOS {
	case "darwin":
		platform = "Macintosh; Intel Mac OS X 10_15_7"
	case "windows":
		platform = "Windows NT 10.0; Win64; x64"
	}
	return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) " +
		"Chrome/131.0.0.0 Safari/537.36"
}()

// isCertificateFailure reports whether a page failed because its server's
// certificate was not accepted, which is common for aTrust appliances.
func isCertificateFailure(description string) bool {
	d := strings.ToLower(description)
	return strings.Contains(d, "ssl") || strings.Contains(d, "certificate") ||
		strings.Contains(d, "证书") || strings.Contains(d, "tls")
}

// pasteLoginHTML is the page shown when the login has to happen in the system
// browser: it explains what to copy and where from.
func pasteLoginHTML(title, intro, loginURL string) string {
	esc := html.EscapeString
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<style>body{font:14px -apple-system,system-ui,sans-serif;padding:18px;color:#1f2328;background:#fff}` +
		`h1{font-size:16px;margin:0 0 10px}p{font-size:13px;line-height:1.6;color:#4a5260;margin:8px 0}` +
		`code{font-family:ui-monospace,monospace;font-size:12px;background:#f2f3f5;padding:1px 4px;border-radius:4px;word-break:break-all}` +
		`input{width:100%;box-sizing:border-box;padding:8px;font-size:12px;border:1px solid #d0d5dd;border-radius:8px;margin-top:6px}` +
		`#err{color:#c62828;font-size:12px;min-height:16px;margin-top:6px}</style></head><body>` +
		`<h1>` + esc(title) + `</h1>` +
		`<p>` + esc(intro) + `</p>` +
		`<p>1. 在浏览器里完成登录；<br>2. 登录成功后地址栏会跳到 <code>https://&lt;服务器&gt;/passport/v1/auth/…</code>；<br>` +
		`3. 把那一整条地址复制下来，粘贴到下面。</p>` +
		`<p>登录页：<code>` + esc(loginURL) + `</code></p>` +
		`<input id="cb" placeholder="粘贴 https://…/passport/v1/auth/… 开头的地址" spellcheck="false">` +
		`<div id="err"></div></body></html>`
}

// isCASLoginURL reports whether the login page is the CAS entry point, which
// is worth replacing with the portal's own address.
func isCASLoginURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(u.Path, "casLogin")
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

// browserLogin completes a login in the system browser: the page is handed
// over, and the callback address the identity provider ends on is pasted back.
// It is the reliable path for portals whose page only works in a real browser.
func (a *app) browserLogin(ctx context.Context, pointName, server, loginURL string) (string, error) {
	logLine := func(format string, args ...any) {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] ", pointName)+fmt.Sprintf(format, args...))
		}
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           "浏览器登录 — " + pointName,
		Width:           640,
		Height:          420,
		MinWidth:        480,
		MinHeight:       320,
		URL:             "about:blank",
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		Page: mygo.PageOptions{
			DevTools:      mygo.DevToolsEnabled,
			PreloadScript: devToolsShortcut,
		},
	})
	if win.IsDestroyed() {
		return "", errors.New("打不开登录窗口")
	}
	page := win.Page()
	if page == nil {
		win.Close()
		return "", errors.New("登录窗口没有网页")
	}
	logLine("用系统浏览器打开登录页：%s", loginPageForLog(loginURL))
	if err := mygo.Shell.OpenExternal(loginURL); err != nil {
		logLine("打开浏览器失败：%v", err)
	}
	page.LoadHTML(pasteLoginHTML("在浏览器里登录 — "+pointName,
		"已用系统浏览器打开登录页，在那边登录即可。", loginURL), "")
	win.Show()
	win.Focus()

	result := make(chan string, 1)
	done := make(chan struct{})
	var once sync.Once
	finish := func(callback string, err error) {
		once.Do(func() {
			if err != nil {
				logLine("浏览器登录未完成：%v", err)
			}
			result <- callback
			close(done)
			win.Close()
		})
	}
	win.OnClose(func(e *mygo.CloseEvent) {
		once.Do(func() {
			result <- ""
			close(done)
		})
	})

	go func() {
		ticker := time.NewTicker(700 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				finish("", ctx.Err())
				return
			case <-ticker.C:
			}
			evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			raw, err := page.EvalContext(evalCtx, pasteProbe)
			cancel()
			if err != nil {
				continue
			}
			href, text := parsePasteProbe(raw)
			reportPageErrors(page, logLine)
			if strings.Contains(href, "#devtools") {
				page.OpenDevTools()
				continue
			}
			text = strings.TrimSpace(text)
			if !strings.HasPrefix(text, "https://") {
				continue
			}
			if callbackFromURLAllowed(text, server) {
				logLine("已收到回调地址")
				finish(text, nil)
				return
			}
			msg, _ := json.Marshal("地址不对：需要 https://" + server + "/passport/v1/auth/ 开头的回调地址")
			evalCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
			_, _ = page.EvalContext(evalCtx2,
				`(function(){var e=document.getElementById('err');if(e){e.textContent=`+string(msg)+`;}})()`)
			cancel2()
		}
	}()

	select {
	case cb := <-result:
		if cb == "" {
			return "", errLoginCanceled
		}
		return cb, nil
	case <-time.After(10 * time.Minute):
		finish("", errors.New("登录超时"))
		return "", errors.New("登录超时")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
