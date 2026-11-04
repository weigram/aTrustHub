package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/egoist/mygo"
)

var settingsPattern = regexp.MustCompile(`(?s)window\.settings\s*=\s*(\{.*?\});`)

// fetchQyWechat gets the older qrconnect page's settings and QR image. Both
// are public; the status key is all the polling needs.
func fetchQyWechat(ctx context.Context, loginURL string) (qyWechatSettings, []byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return qyWechatSettings{}, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return qyWechatSettings{}, nil, err
	}
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return qyWechatSettings{}, nil, fmt.Errorf("二维码页返回 %d", resp.StatusCode)
	}
	m := settingsPattern.FindSubmatch(page)
	if len(m) < 2 {
		return qyWechatSettings{}, nil, fmt.Errorf("二维码页没有设置")
	}
	var settings qyWechatSettings
	if err := json.Unmarshal(m[1], &settings); err != nil {
		return qyWechatSettings{}, nil, err
	}
	if settings.Key == "" || settings.QRURL == "" {
		return qyWechatSettings{}, nil, fmt.Errorf("二维码页缺少 key")
	}
	qrURL := settings.QRURL
	switch {
	case strings.HasPrefix(qrURL, "//"):
		qrURL = "https:" + qrURL
	case strings.HasPrefix(qrURL, "/"):
		qrURL = "https://open.work.weixin.qq.com" + qrURL
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, qrURL, nil)
	if err != nil {
		return qyWechatSettings{}, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err = client.Do(req)
	if err != nil {
		return qyWechatSettings{}, nil, err
	}
	img, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(img) == 0 {
		return qyWechatSettings{}, nil, fmt.Errorf("二维码图片返回 %d", resp.StatusCode)
	}
	return settings, img, nil
}

// wecomStaticHTML builds a script-free page that shows one QR image. There is
// no JavaScript, no external resource and no polling in the page: the login
// is driven entirely from Go, so the WebView can never freeze on the page's
// own scripts.
func wecomStaticHTML(title, instruction string, png []byte, showLocalBtn bool) string {
	b64 := base64.StdEncoding.EncodeToString(png)
	btn := ""
	if showLocalBtn {
		btn = `<a id="local" href="#local" onclick="location.hash='local';return false;">本地企业微信认证</a>`
	}
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<style>` +
		`html,body{margin:0;height:100%;}` +
		`body{display:flex;align-items:center;justify-content:center;` +
		`font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;` +
		`background:#fff;color:#222;}` +
		`.wrap{display:flex;flex-direction:column;align-items:center;gap:14px;padding:24px;}` +
		`h1{font-size:16px;font-weight:600;margin:0;}` +
		`img{width:240px;height:240px;image-rendering:pixelated;border:1px solid #eee;border-radius:8px;}` +
		`p{font-size:12px;line-height:1.6;color:#666;margin:0;text-align:center;max-width:300px;}` +
		`#local{display:inline-block;margin-top:6px;padding:9px 18px;border-radius:8px;` +
		`background:#1769e0;color:#fff;font-size:13px;text-decoration:none;cursor:pointer;}` +
		`#local:hover{background:#1257bd;}` +
		`</style></head><body><div class="wrap">` +
		`<h1>` + html.EscapeString(title) + `</h1>` +
		`<img alt="二维码" src="data:image/png;base64,` + b64 + `">` +
		`<p>` + html.EscapeString(instruction) + `</p>` +
		btn +
		`</div></body></html>`
}

// openStaticQRWindow shows png in a small WebView that loads only the static
// page above, then blocks until done() fires (login finished elsewhere), the
// user closes the window, or ctx ends. When showLocalBtn is set, the page
// shows a "本地企业微信认证" button that, clicked, calls onLocalLogin (the
// desktop quick-login path). The window itself never reports the login
// result; the caller's poller does.
func openStaticQRWindow(ctx context.Context, title, instruction string, png []byte, showLocalBtn bool, onLocalLogin func(say func(string)), done <-chan struct{}, onClose func()) error {
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           title,
		Width:           360,
		Height:          500,
		MinWidth:        300,
		MinHeight:       420,
		URL:             "about:blank",
		BackgroundColor: "light-dark(#ffffff, #ffffff)",
	})
	if win.IsDestroyed() {
		return errors.New("打不开二维码窗口")
	}
	page := win.Page()
	if page == nil {
		win.Close()
		return errors.New("二维码窗口没有网页")
	}
	// say rewrites the instruction line, so a click always ends with a visible
	// answer instead of looking like nothing happened.
	say := func(msg string) {
		if page == nil {
			return
		}
		quoted, err := json.Marshal(msg)
		if err != nil {
			return
		}
		evalCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = page.EvalContext(evalCtx,
			`(function(){var p=document.querySelector('p');if(p){p.textContent=`+string(quoted)+`;}})()`)
	}

	var closed bool
	closedCh := make(chan struct{})
	win.OnClose(func(e *mygo.CloseEvent) {
		if !closed {
			closed = true
			if onClose != nil {
				onClose()
			}
			close(closedCh)
		}
	})
	page.OnWillNavigate(func(e *mygo.NavigateEvent) {
		if strings.HasPrefix(e.URL, "wwlocal://") {
			e.PreventDefault()
			if onLocalLogin != nil {
				go onLocalLogin(say)
			}
		}
	})
	page.LoadHTML(wecomStaticHTML(title, instruction, png, showLocalBtn), "")
	// Activate the app first: a new window created while the app is in the
	// background can open behind other apps, which looks like nothing happened.
	mygo.App.Focus()
	win.Show()
	win.Focus()

	// Watch for the "本地企业微信认证" button. The button sets location.hash
	// to "#local"; polling that tiny string once a second is negligible on
	// this script-free page and cannot freeze the app.
	if showLocalBtn && onLocalLogin != nil {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-closedCh:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				evalCtx, c := context.WithTimeout(ctx, 2*time.Second)
				raw, err := page.EvalContext(evalCtx, "location.hash")
				c()
				if err != nil {
					continue
				}
				if h, ok := raw.(string); ok && strings.Contains(h, "local") {
					go onLocalLogin(say)
					return
				}
			}
		}()
	}

	select {
	case <-done:
		win.Close()
	case <-closedCh:
		// The user closed the window.
	case <-ctx.Done():
		win.Close()
	}
	return nil
}

// wecomStaticQRLogin runs WeCom's new web login without ever loading its
// official page: it fetches the QR image, shows it on a static page, and polls
// the status endpoint from Go. Both scanning the QR and confirming in the
// desktop client work, because both drive the same status endpoint.
func (a *app) wecomStaticQRLogin(ctx context.Context, pointName, server, loginURL string) (string, error, bool) {
	if a.win == nil {
		return "", nil, false
	}
	settings, err := fetchWWLoginSettings(ctx, loginURL)
	if err != nil {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] 读取企业微信登录参数失败：%v", pointName, err))
		}
		return "", nil, false
	}
	logLine := func(format string, args ...any) {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] ", pointName)+fmt.Sprintf(format, args...))
		}
	}
	logLine("企业微信网页登录参数已读取")

	// Fetch the QR image (same key the official page uses). The deadline keeps
	// a stalled connection from leaving the click with no visible reaction.
	logLine("开始获取二维码图片：%s", qrHost(settings.QRURL))
	png, err := fetchWeComQRImage(ctx, settings)
	if err != nil {
		logLine("获取二维码图片失败：%v", err)
		return "", nil, false
	}

	instruction := "用手机企业微信扫一扫二维码登录；或点下方按钮用本机企业微信免扫码登录。"

	done := make(chan struct{})
	userClosed := make(chan struct{}, 1)
	cbCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Poll the status from Go. Scanning the QR drives the same endpoint, so
	// the scan path needs nothing else. The desktop "免扫码" path is started
	// only when the user clicks the button, below.
	go func() {
		cb, _, err := a.pollWeComLogin(ctx, pointName, server, loginURL, settings, false, 0, logLine)
		if err != nil {
			errCh <- err
		} else {
			cbCh <- cb
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	// The "本地企业微信认证" button: detect the desktop client and ask it to
	// confirm (免扫码). Scanning still works at any time.
	onLocalLogin := func(say func(string)) {
		say("正在查找电脑版企业微信…")
		ports := append(append([]int{}, settings.HTTPSPorts...), 50010, 50011, 50012, 50013)
		port, desktop := wecomDesktopState(ctx, ports, loginURL, settings.RedirectURI)
		if !desktop {
			logLine("未检测到电脑企业微信（已尝试端口 %v），请在手机企业微信扫码登录", ports)
			say("未检测到电脑版企业微信，请在手机上扫码（先打开企业微信客户端可免扫码）")
			return
		}
		logLine("检测到电脑企业微信（端口 %d），发送确认请求", port)
		say("已找到电脑版企业微信，请在弹出的窗口点击确认")
		if err := wecomBindWeCom(ctx, port, loginURL, settings.ClientKey); err != nil {
			logLine("发送确认请求失败：%v", err)
			say("发送确认请求失败：" + err.Error())
			return
		}
		logLine("已请求电脑企业微信确认，请在企业微信里点「确认登录」")
	}

	winErr := openStaticQRWindow(ctx, "企业微信扫码登录 — "+pointName, instruction, png, true, onLocalLogin, done, func() {
		select {
		case userClosed <- struct{}{}:
		default:
		}
	})
	if winErr != nil {
		return "", winErr, true
	}

	select {
	case cb := <-cbCh:
		return cb, nil, true
	case err := <-errCh:
		return "", err, true
	case <-userClosed:
		// The window was closed; but a result may have arrived at the same
		// moment as the auto-close. Prefer a real result if one is ready.
		select {
		case cb := <-cbCh:
			return cb, nil, true
		case err := <-errCh:
			return "", err, true
		default:
		}
		return "", errLoginCanceled, true
	case <-ctx.Done():
		return "", ctx.Err(), true
	}
}

// qywechatStaticQRLogin is the older-page variant: it reads the QR image from
// the qrconnect page (settings + image, both public) and shows it on a static
// page, polling the status from Go.
func (a *app) qywechatStaticQRLogin(ctx context.Context, pointName, server, loginURL string) (string, error, bool) {
	if a.win == nil {
		return "", nil, false
	}
	settings, qrPNG, err := fetchQyWechat(ctx, loginURL)
	if err != nil {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] 读取二维码失败：%v", pointName, err))
		}
		return "", nil, false
	}
	logLine := func(format string, args ...any) {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] ", pointName)+fmt.Sprintf(format, args...))
		}
	}
	logLine("二维码已获取，打开扫码窗口")

	done := make(chan struct{})
	userClosed := make(chan struct{}, 1)
	cbCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		cb, err := a.pollQyWechatStatic(ctx, pointName, server, settings, logLine)
		if err != nil {
			errCh <- err
		} else {
			cbCh <- cb
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	instruction := "请使用手机企业微信扫描二维码，并在手机上点「确认登录」。"
	winErr := openStaticQRWindow(ctx, "企业微信扫码登录 — "+pointName, instruction, qrPNG, false, nil, done, func() {
		select {
		case userClosed <- struct{}{}:
		default:
		}
	})
	if winErr != nil {
		return "", winErr, true
	}

	select {
	case cb := <-cbCh:
		return cb, nil, true
	case err := <-errCh:
		return "", err, true
	case <-userClosed:
		select {
		case cb := <-cbCh:
			return cb, nil, true
		case err := <-errCh:
			return "", err, true
		default:
		}
		return "", errLoginCanceled, true
	case <-ctx.Done():
		return "", ctx.Err(), true
	}
}

// fetchWeComQRImage loads the QR image for the web login key.
func fetchWeComQRImage(ctx context.Context, settings wwLoginSettings) ([]byte, error) {
	qrURL := settings.QRURL
	switch {
	case strings.HasPrefix(qrURL, "//"):
		qrURL = "https:" + qrURL
	case strings.HasPrefix(qrURL, "/"):
		qrURL = "https://login.work.weixin.qq.com" + qrURL
	}
	// Make sure the URL carries our web key.
	if settings.WebKey != "" && strings.Contains(qrURL, "key=") {
		if i := strings.Index(qrURL, "key="); i >= 0 {
			rest := qrURL[i+4:]
			if j := strings.IndexByte(rest, '&'); j >= 0 {
				rest = rest[j:]
			} else {
				rest = ""
			}
			qrURL = qrURL[:i+4] + settings.WebKey + rest
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, qrURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(b) == 0 {
		return nil, errors.New("二维码图片为空")
	}
	return b, nil
}

// qrHost is the host of a QR URL, for logs.
func qrHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

// pollQyWechatStatic polls the older QR status from Go and returns the code.
func (a *app) pollQyWechatStatic(ctx context.Context, pointName, server string, settings qyWechatSettings, logLine func(string, ...any)) (string, error) {
	deadline := time.Now().Add(3 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return "", errors.New("企业微信登录超时")
		}
		poll, err := pollQyWechatStatus(ctx, settings, nil, func(status string) {
			logLine("扫码状态：%s", status)
		})
		if err != nil {
			if errors.Is(err, errQRExpired) {
				return "", errors.New("二维码已过期，请重新登录")
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
			continue
		}
		redirect := poll.RedirectURI
		if redirect == "" {
			redirect = settings.RedirectURI
		}
		callback, cerr := qyWechatCallback(redirect, settings, poll.AuthCode)
		if cerr != nil || !callbackFromURLAllowed(callback, server) {
			return "", errors.New("二维码回调地址不完整")
		}
		logLine("手机已确认，收到扫码回调")
		return callback, nil
	}
}
