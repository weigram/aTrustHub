package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/vpn"
)

// codePrompt is the window that asks for a one-time code: an SMS code, a
// dynamic password, a RADIUS token. Every field is written on the main thread
// (the view and its input handlers run there), so it needs no lock.
type codePrompt struct {
	label  string
	hint   string
	value  string
	errMsg string
	// focus is the control wanted focused; FocusBind writes the actual focus
	// back here, so a refused submit can put it back on the field.
	focus  string
	submit func(code string)
}

func (p *codePrompt) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Padding(18).Gap(10).Children(func() {
		ui.Text(c, p.label).FontSize(16).Bold()
		ui.Text(c, p.hint).FontSize(12).TextColor(t.TextMuted).Wrap()
		in := ui.TextInput(c, &p.value)
		in.AutoFocus().FocusBind(&p.focus, "code")
		in.OnSubmit(func() { p.accept(c) })
		if p.errMsg != "" {
			ui.Text(c, p.errMsg).FontSize(11).TextColor(t.Danger)
		}
		ui.Spacer(c)
		ui.Row(c).Justify(ui.End).Children(func() {
			if ui.PrimaryButton(c, "确定").Clicked() {
				p.accept(c)
			}
		})
	})
}

func (p *codePrompt) accept(c *ui.Context) {
	code := strings.TrimSpace(p.value)
	if code == "" {
		p.errMsg = "请输入验证码"
		p.focus = "code"
		c.Invalidate()
		return
	}
	if p.submit == nil {
		return
	}
	submit := p.submit
	p.submit = nil
	submit(code)
}

func (a *app) askLoginCode(ctx context.Context, pointName string, req vpn.CodeRequest) (string, error) {
	if a.win == nil {
		return "", errors.New("主窗口还没有打开")
	}
	// 不占 externalLogin 的登录窗口互斥量：验证码窗口只开几秒，排在一个
	// 可能开着几分钟的扫码窗口后面，只会让登录看起来卡住。
	label, hint := codePromptText(req)
	answer := make(chan string, 1)
	prompt := &codePrompt{label: label, hint: hint, focus: "code"}
	prompt.submit = func(code string) {
		select {
		case answer <- code:
		default:
		}
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           label + " — " + pointName,
		Width:           440,
		Height:          250,
		MinWidth:        380,
		MinHeight:       240,
		MaxWidth:        620,
		MaxHeight:       460,
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		Content:         ui.View(prompt.view),
	})
	if win.IsDestroyed() {
		return "", errors.New("打不开验证码窗口")
	}
	if a.bus != nil {
		a.bus.Add("app", fmt.Sprintf("[%s] 等待%s", pointName, label))
	}
	// 关窗只发一个信号，窗口在这之后由本函数关闭——mygo 的 Close 会在
	// 调用线程上同步跑 OnClose，在回调里关窗会和回调互等。
	closed := make(chan struct{}, 1)
	win.OnClose(func(e *mygo.CloseEvent) {
		select {
		case closed <- struct{}{}:
		default:
		}
	})
	win.Show()
	win.Focus()
	defer win.Close()

	select {
	case code := <-answer:
		return code, nil
	case <-closed:
		return "", errors.New("已取消输入验证码")
	case <-time.After(5 * time.Minute):
		return "", errors.New("验证码输入超时，请重新登录")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func codePromptText(req vpn.CodeRequest) (label, hint string) {
	switch req.Kind {
	case vpn.CodeSMS:
		label = "短信验证码"
		hint = req.Tip
		if hint == "" {
			hint = "验证码已发送到您的手机"
		}
		hint += " 若在验证码前加 $，会跳过二次认证。"
	case vpn.CodeCustomSMS:
		label = "验证码"
		hint = req.Tip
	case vpn.CodeTOTP:
		label = "动态口令"
		hint = "请输入手机上的动态口令"
	case vpn.CodeRADIUS:
		label = "RADIUS 令牌"
		hint = "请输入令牌"
	}
	return label, hint
}
