package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// pastePrompt is the window that asks for the callback address a login in the
// system browser ends on. It is the reliable path when the WebView refuses the
// server's certificate, and the only path for portals whose page needs a real
// browser.
type pastePrompt struct {
	intro    string
	loginURL string
	server   string
	value    string
	errMsg   string
	// focus is the control wanted focused; FocusBind writes the actual focus
	// back here, so a refused address can put it back on the field.
	focus  string
	submit func(callback string)
}

func (p *pastePrompt) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(18).Gap(10).Children(func() {
		ui.Scroll(c).Grow(1).Children(func() {
			ui.Column(c).Gap(8).Children(func() {
				ui.Text(c, p.intro).FontSize(12).TextColor(t.TextMuted).Wrap()
				ui.Text(c, "1. 在浏览器里完成登录").FontSize(12)
				ui.Text(c, "2. 登录成功后地址栏会跳到 https://<服务器>/passport/v1/auth/…").FontSize(12).Wrap()
				ui.Text(c, "3. 把那一整条地址复制下来，粘贴到下面").FontSize(12)
				ui.Text(c, "如果地址已经跳走了：在浏览器里再打开一次上面的登录页（登录状态还在），"+
					"地址栏会立刻重新出现带 ticket 的地址；或者在历史记录里搜索 auth/cas 找到它。").
					FontSize(12).TextColor(t.TextMuted).Wrap()
				ui.Text(c, "登录页："+p.loginURL).FontSize(11).TextColor(t.TextMuted).Selectable().Wrap()
			})
		})
		in := ui.TextInput(c, &p.value)
		in.Placeholder("粘贴 https://…/passport/v1/auth/… 开头的地址").AutoFocus().FocusBind(&p.focus, "cb")
		in.OnSubmit(func() { p.accept(c) })
		if p.errMsg != "" {
			ui.Text(c, p.errMsg).FontSize(11).TextColor(t.Danger)
		}
		ui.Row(c).Justify(ui.End).Children(func() {
			if ui.PrimaryButton(c, "确定").Clicked() {
				p.accept(c)
			}
		})
	})
}

func (p *pastePrompt) accept(c *ui.Context) {
	text := strings.TrimSpace(p.value)
	if text == "" {
		return
	}
	if !callbackFromURLAllowed(text, p.server) {
		p.errMsg = "地址不对：需要以 https://" + p.server + "/passport/v1/auth/ 开头的回调地址"
		p.focus = "cb"
		c.Invalidate()
		return
	}
	if p.submit == nil {
		return
	}
	submit := p.submit
	p.submit = nil
	submit(text)
}

// pasteLoginWindow opens the login page in the system browser and waits for
// the callback address pasted into a small window. It returns errLoginCanceled
// when the user closes that window.
func (a *app) pasteLoginWindow(ctx context.Context, pointName, server, loginURL, title, intro string) (string, error) {
	logLine := func(format string, args ...any) {
		if a.bus != nil {
			a.bus.Add("app", fmt.Sprintf("[%s] ", pointName)+fmt.Sprintf(format, args...))
		}
	}
	logLine("用系统浏览器打开登录页：%s", loginPageForLog(loginURL))
	if err := mygo.Shell.OpenExternal(loginURL); err != nil {
		logLine("打开浏览器失败：%v", err)
	}

	answer := make(chan string, 1)
	prompt := &pastePrompt{intro: intro, loginURL: loginURL, server: server, focus: "cb"}
	prompt.submit = func(callback string) {
		select {
		case answer <- callback:
		default:
		}
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           title,
		Width:           640,
		Height:          420,
		MinWidth:        480,
		MinHeight:       320,
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		Content:         ui.View(prompt.view),
	})
	if win.IsDestroyed() {
		return "", errors.New("打不开登录窗口")
	}
	// 关窗只发一个信号，窗口在这之后由本函数关闭。
	closed := make(chan struct{}, 1)
	win.OnClose(func(e *mygo.CloseEvent) {
		select {
		case closed <- struct{}{}:
		default:
		}
	})
	// 新窗口开在后台时会藏在别的应用后面，看起来像什么都没发生。
	mygo.App.Focus()
	win.Show()
	win.Focus()
	defer win.Close()

	select {
	case callback := <-answer:
		logLine("已收到回调地址")
		return callback, nil
	case <-closed:
		return "", errLoginCanceled
	case <-time.After(10 * time.Minute):
		return "", errors.New("登录超时")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
