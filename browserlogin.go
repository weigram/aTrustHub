package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/qy/easyconnect/internal/cdp"
	"github.com/qy/easyconnect/internal/model"
)

// 单点登录用真正的浏览器完成，再把「授权码」交给客户端自己去登录。
//
// 为什么不能直接把浏览器的 cookie 拿来用：TCP 隧道要校验签名和设备号
// （服务器回 sig or deviceId verify failed），浏览器里的会话属于「网页
// 客户端」，换一个设备号根本过不去。所以这里只借用浏览器的身份会话去换
// 一张票，登录仍然由客户端自己做，会话才是它自己的。
func (a *app) cdpLoginCallback(ctx context.Context, point *model.AccessPoint, loginURL string) (string, error) {
	if point == nil {
		return "", errors.New("接入点不存在")
	}
	name := point.Name
	logf := func(format string, args ...any) {
		a.tunLogf("[%s] "+format, append([]any{name}, args...)...)
	}
	if !a.browserLoginMu.TryLock() {
		return "", errors.New("已经在用浏览器登录，请在弹出的窗口里完成")
	}
	defer a.browserLoginMu.Unlock()

	exe := browserExecutable()
	if exe == "" {
		return "", errors.New("没有找到 Chrome 或 Edge，请先安装其中一个")
	}
	host := point.Server
	if point.Port != 0 && point.Port != 443 {
		host = fmt.Sprintf("%s:%d", point.Server, point.Port)
	}
	profile := filepath.Join(a.dir, "browser", point.ID)
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return "", fmt.Errorf("无法创建浏览器配置目录：%w", err)
	}

	port, err := cdp.FreePort()
	if err != nil {
		return "", fmt.Errorf("无法分配调试端口：%w", err)
	}

	// 上次留下的浏览器还在跑就直接用它，否则新启动会被它接管、端口不监听。
	var client *cdp.Client
	var proc *browserProc
	if st, ok := readBrowserState(a.dir, point.ID); ok {
		if c, err := cdp.AttachFor(ctx, st.Port, host); err == nil {
			client, port = c, st.Port
			logf("复用已打开的浏览器（调试端口 %d）", port)
		}
	}
	if client == nil {
		logf("浏览器登录：启动 %s，调试端口 %d", filepath.Base(exe), port)
		proc, err = launchBrowser(exe, profile, port, loginURL)
		if err != nil {
			return "", fmt.Errorf("启动浏览器失败：%w", err)
		}
		writeBrowserState(a.dir, point.ID, browserState{PID: proc.cmd.Process.Pid, Port: port})
		client, err = attachWhenReady(ctx, port, host)
		if err != nil {
			// 同一配置目录已有实例时，新启动会被接管并立即退出，端口不会打开。
			// 用户把窗口关掉时不要再启动一个：那看起来像是「关了又弹」。
			if proc.Exited() {
				return "", errors.New("浏览器已关闭")
			}
			logf("浏览器 18 秒内没有响应（%v），改用临时配置目录重试；这一次不会带上已保存的密码与登录状态", err)
			proc.Stop()
			unique := fmt.Sprintf("%s-%d", profile, time.Now().Unix())
			port, err = cdp.FreePort()
			if err != nil {
				return "", fmt.Errorf("无法分配调试端口：%w", err)
			}
			proc, err = launchBrowser(exe, unique, port, loginURL)
			if err != nil {
				return "", fmt.Errorf("启动浏览器失败：%w", err)
			}
			writeBrowserState(a.dir, point.ID, browserState{PID: proc.cmd.Process.Pid, Port: port})
			client, err = attachWhenReady(ctx, port, host)
			if err != nil {
				return "", fmt.Errorf("连接浏览器失败：%w", err)
			}
		}
		defer stopBrowser(client, proc)
	} else {
		// 复用的浏览器不是这次启动的，结束时按记录的进程号关掉。
		defer closeLoginBrowser(a.dir, point.ID)
	}
	defer client.Close()
	if err := client.Enable(ctx); err != nil {
		logf("开启调试域失败：%v", err)
	}
	defer clearBrowserState(a.dir, point.ID)

	// 直接打开服务器的认证地址：它会 302 到身份提供方，登录后在同一
	// 标签页里带着票跳回来。这样不会冒出第二个标签页，也就不会出现
	// 「界面停在空白新标签页上」。
	logf("请在打开的浏览器里完成登录，登录成功后会自动继续")
	// 只拦 passport 的回调。门户的 shortcut.html 里那个 data.ticket 是票
	// 换过一次之后的产物，拿它再去换票会被服务器拒绝（data not found）。
	pattern := fmt.Sprintf("*://%s/passport/v1/auth/*", host)
	if err := client.PauseRequests(ctx, pattern); err != nil {
		return "", fmt.Errorf("无法拦截回跳地址：%w", err)
	}

	got := make(chan string, 1)
	client.OnEvent(func(method string, params json.RawMessage) {
		if method != "Fetch.requestPaused" {
			return
		}
		var ev struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if json.Unmarshal(params, &ev) != nil || ev.Request.URL == "" {
			return
		}
		// 只认接入点自己域名下的回调；身份提供方那边同名的路径要放行，
		// 否则会把登录自己的跳转卡死。
		u, err := url.Parse(ev.Request.URL)
		if err != nil || !strings.EqualFold(u.Host, host) ||
			!strings.Contains(u.Path, "/passport/v1/auth/") {
			if err == nil {
				go client.ContinueRequest(context.Background(), ev.RequestID)
			}
			return
		}
		// 让它失败，而不是放过去：票只能用一次，交给我们用。
		dropCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = client.DropRequest(dropCtx, ev.RequestID)
		cancel()
		select {
		case got <- ev.Request.URL:
		default:
		}
	})

	if err := client.Navigate(ctx, loginURL); err != nil {
		return "", fmt.Errorf("打开认证地址失败：%w", err)
	}

	// 登录可能在新标签页里完成：发现新页面就跟上去，同样拦它的请求。
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case url := <-got:
			logf("已取得回调地址，交由客户端登录")
			return url, nil
		case <-ticker.C:
			if !pageAlive(ctx, client) {
				next, err := cdp.AttachFor(ctx, port, host)
				if err != nil {
					return "", errors.New("浏览器已关闭")
				}
				_ = client.Close()
				client = next
				_ = client.PauseRequests(ctx, fmt.Sprintf("*://%s/passport/v1/auth/*", host))
				logf("登录页已切换到新的标签页")
			}
		}
	}
}

// pageAlive reports whether the attached page still answers.
func pageAlive(ctx context.Context, client *cdp.Client) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var href string
	return client.Evaluate(probeCtx, `location.href`, &href) == nil
}

// launchBrowser starts a Chromium for the login window, with its own profile
// and a DevTools port.
// browserProc is a launched browser plus a way to tell whether it is gone.
type browserProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func launchBrowser(exe, profile string, port int, start string) (*browserProc, error) {
	cmd := exec.Command(exe,
		fmt.Sprintf("--remote-debugging-port=%d", port),
		"--user-data-dir="+profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-sync",
		// 自签证书不忽略的话页面停在证书错误上，会话根本建立不起来。
		"--ignore-certificate-errors",
		start,
	)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &browserProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_, _ = cmd.Process.Wait()
		close(p.done)
	}()
	return p, nil
}

// stopBrowser asks the browser to close itself so it flushes its profile —
// cookies, and the password the user may have just saved — then kills it if it
// is still there. Killing straight away is why a saved password could disappear
// between two logins.
func stopBrowser(client *cdp.Client, proc *browserProc) {
	if proc == nil {
		return
	}
	if client != nil {
		// 给「保存密码」的提示条留一点时间：它出现在登录提交之后，
		// 立刻关窗等于把它一起关掉，下次自然就没有可填的密码。
		time.Sleep(1500 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = client.CloseBrowser(ctx)
		cancel()
		select {
		case <-proc.done:
			return
		case <-time.After(3 * time.Second):
		}
	}
	proc.Stop()
}

// Exited reports whether the browser was closed.
func (p *browserProc) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Stop closes the browser and waits for it to go away.
func (p *browserProc) Stop() {
	if p == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
	}
}

// attachWhenReady waits for the freshly started browser's DevTools endpoint.
//
// The budget is generous on purpose: a first start on a cold machine (Windows
// especially) can take well over ten seconds. Timing out early is not free —
// the caller then falls back to a throw-away profile, which loses the cookies
// and saved passwords the user built up in the real one.
func attachWhenReady(ctx context.Context, port int, host string) (*cdp.Client, error) {
	var lastErr error
	for i := 0; i < 60; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
		client, err := cdp.AttachFor(ctx, port, host)
		if err == nil {
			return client, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("浏览器没有响应")
	}
	return nil, lastErr
}

// browserState remembers the login browser of a point, so the next attempt
// attaches to it instead of starting a second one on the same profile.
type browserState struct {
	PID  int `json:"pid"`
	Port int `json:"port"`
}

func browserStatePath(dir, id string) string {
	return filepath.Join(dir, "browser", id+".json")
}

func readBrowserState(dir, id string) (browserState, bool) {
	var st browserState
	data, err := os.ReadFile(browserStatePath(dir, id))
	if err != nil {
		return st, false
	}
	if err := json.Unmarshal(data, &st); err != nil || st.Port == 0 {
		return st, false
	}
	return st, true
}

func writeBrowserState(dir, id string, st browserState) {
	path := browserStatePath(dir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(st); err == nil {
		_ = os.WriteFile(path, data, 0o600)
	}
}

// closeLoginBrowser stops a browser this app started for a point's login.
func closeLoginBrowser(dir, id string) {
	st, ok := readBrowserState(dir, id)
	if !ok {
		return
	}
	if proc, err := os.FindProcess(st.PID); err == nil {
		_ = proc.Kill()
	}
	clearBrowserState(dir, id)
}

func clearBrowserState(dir, id string) {
	_ = os.Remove(browserStatePath(dir, id))
}

// browserExecutable finds a Chromium browser that accepts the DevTools port.
func browserExecutable() string {
	switch runtime.GOOS {
	case "darwin":
		for _, p := range []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	case "windows":
		candidates := []string{
			filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		}
		for _, p := range candidates {
			if p == "" {
				continue
			}
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	return ""
}
