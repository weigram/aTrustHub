package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/egoist/mygo"

	"github.com/qy/easyconnect/internal/vpn"
)

// codeProbe reads the field and the submit flag in one poll.
const codeProbe = `(function(){
  var b = document.getElementById('code');
  return JSON.stringify([b ? b.value : '', window.__go ? 1 : 0]);
})()`

func parseCodeProbe(raw any) (value string, submitted bool) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	var parts []any
	if err := json.Unmarshal([]byte(s), &parts); err != nil || len(parts) != 2 {
		return "", false
	}
	value, _ = parts[0].(string)
	n, _ := parts[1].(float64)
	return value, n == 1
}

func (a *app) askLoginCode(ctx context.Context, pointName string, req vpn.CodeRequest) (string, error) {
	if a.win == nil {
		return "", errors.New("主窗口还没有打开")
	}
	// 不占 externalLogin 的登录窗口互斥量：验证码窗口只开几秒，排在一个
	// 可能开着几分钟的扫码窗口后面，只会让登录看起来卡住。
	label, hint := codePromptText(req)
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           label + " — " + pointName,
		Width:           440,
		Height:          250,
		MinWidth:        380,
		MinHeight:       240,
		MaxWidth:        620,
		MaxHeight:       460,
		URL:             "about:blank",
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		Page:            mygo.PageOptions{DevTools: mygo.DevToolsEnabled},
	})
	if win.IsDestroyed() {
		return "", errors.New("打不开验证码窗口")
	}
	page := win.Page()
	if page == nil {
		win.Close()
		return "", errors.New("验证码窗口没有网页")
	}
	if a.bus != nil {
		a.bus.Add("app", fmt.Sprintf("[%s] 等待%s", pointName, label))
	}
	page.LoadHTML(codePromptHTML(label, hint), "")
	win.Show()
	win.Focus()

	type answer struct {
		code string
		err  error
	}
	// 一个回答就走人：谁先送到算谁的，后来的丢掉。关窗口只能发生在这
	// 之后——mygo 的 Close 会在调用线程上同步跑 OnClose，在 Once 里面关
	// 窗口会和 OnClose 里的 Once 互等。
	result := make(chan answer, 1)
	post := func(code string, err error) {
		select {
		case result <- answer{code: code, err: err}:
		default:
		}
	}
	win.OnClose(func(e *mygo.CloseEvent) {
		post("", errors.New("已取消输入验证码"))
	})

	stop := make(chan struct{})
	defer close(stop)
	defer win.Close()

	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				post("", ctx.Err())
				return
			case <-ticker.C:
			}
			evalCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			raw, err := page.EvalContext(evalCtx, codeProbe)
			cancel()
			if err != nil {
				continue
			}
			value, submitted := parseCodeProbe(raw)
			if !submitted {
				continue
			}
			value = strings.TrimSpace(value)
			if value == "" {
				msg, _ := json.Marshal("请输入验证码")
				evalCtx2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
				_, _ = page.EvalContext(evalCtx2,
					`(function(){var e=document.getElementById('err');if(e){e.textContent=`+string(msg)+`;}window.__go=0;})()`)
				cancel2()
				continue
			}
			post(value, nil)
			return
		}
	}()

	select {
	case res := <-result:
		return res.code, res.err
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

func codePromptHTML(label, hint string) string {
	esc := html.EscapeString
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<style>html,body{height:100%}` +
		`body{margin:0;padding:16px 18px;box-sizing:border-box;display:flex;flex-direction:column;` +
		`font:14px -apple-system,system-ui,sans-serif;color:#1f2328;background:#fff}` +
		`h1{font-size:16px;margin:0 0 8px}` +
		`p{flex:0 1 auto;font-size:13px;line-height:1.6;color:#4a5260;margin:0 0 6px;min-height:2.2em;overflow-y:auto}` +
		`input{flex:none;width:100%;box-sizing:border-box;padding:8px;font-size:14px;border:1px solid #d0d5dd;border-radius:8px}` +
		`input:focus{outline:0;border-color:#1f6feb;box-shadow:0 0 0 3px rgba(31,111,235,.18)}` +
		`#err{flex:none;color:#c62828;font-size:12px;min-height:16px;margin-top:6px}` +
		`button{flex:none;margin:auto 0 0 auto;padding:7px 16px;font-size:13px;border:0;border-radius:8px;` +
		`background:#1f6feb;color:#fff;align-self:flex-end}</style></head><body>` +
		`<h1>` + esc(label) + `</h1>` +
		`<p>` + esc(hint) + `</p>` +
		`<input id="code" autocomplete="one-time-code" spellcheck="false" autofocus>` +
		`<div id="err"></div>` +
		`<button onclick="window.__go=1">确定</button>` +
		`<script>document.getElementById('code').addEventListener('keydown',function(e){` +
		`if(e.key==='Enter'){window.__go=1;}});</script>` +
		`</body></html>`
}
