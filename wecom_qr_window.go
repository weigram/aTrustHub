package main

import (
	"context"
	"errors"
	"sync"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

// qrPrompt is the window that shows one QR image while the login is driven
// from Go. The image is static and nothing runs in the window, so it can never
// freeze; when showLocal is set, a button starts the desktop client's quick
// login instead of scanning.
type qrPrompt struct {
	title     string
	img       *ui.Bitmap
	showLocal bool
	local     func()
	// mu guards instruction: a background goroutine rewrites it as the login
	// progresses, while the view reads it on the main thread.
	mu          sync.Mutex
	instruction string
	closed      chan struct{}
}

func (p *qrPrompt) say(msg string) {
	p.mu.Lock()
	p.instruction = msg
	p.mu.Unlock()
}

func (p *qrPrompt) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.instruction
}

func (p *qrPrompt) view(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Fill().Center().Gap(12).Padding(24).Children(func() {
		ui.Text(c, p.title).FontSize(16).Bold()
		if p.img != nil {
			// 二维码要按像素放大：插值会把码糊掉，扫不出来。
			ui.Image(c, p.img).Size(240, 240)
		}
		ui.Text(c, p.text()).FontSize(12).TextColor(t.TextMuted).TextAlign(ui.Center).Wrap()
		if p.showLocal && p.local != nil {
			if ui.PrimaryButton(c, "本地企业微信认证").Clicked() {
				go p.local()
			}
		}
	})
}

// openStaticQRWindow shows png until done() fires (the login finished
// elsewhere), the user closes the window, or ctx ends. When showLocalBtn is
// set, the button calls onLocalLogin (the desktop quick-login path); its say
// rewrites the instruction line, so an attempt always ends with a visible
// answer instead of looking like nothing happened.
func openStaticQRWindow(ctx context.Context, title, instruction string, png []byte, showLocalBtn bool, onLocalLogin func(say func(string)), done <-chan struct{}, onClose func()) error {
	img, err := ui.DecodeBitmap(png)
	if err != nil {
		return errors.New("二维码图片读不出来")
	}
	img.Pixelated()
	p := &qrPrompt{
		title:       title,
		img:         img,
		showLocal:   showLocalBtn,
		instruction: instruction,
		closed:      make(chan struct{}),
	}
	win := mygo.NewWindow(mygo.WindowOptions{
		Title:           title,
		Width:           360,
		Height:          500,
		MinWidth:        300,
		MinHeight:       420,
		BackgroundColor: "light-dark(#ffffff, #1e1e1e)",
		Content:         ui.View(p.view),
	})
	if win.IsDestroyed() {
		return errors.New("打不开二维码窗口")
	}
	if showLocalBtn && onLocalLogin != nil {
		p.local = func() {
			onLocalLogin(func(msg string) {
				p.say(msg)
				win.Update(func() {})
			})
		}
	}

	// 关窗只发一个信号：窗口在这之后由本函数关闭，回调里不关窗——mygo 的
	// Close 会在调用线程上同步跑 OnClose。
	var once sync.Once
	win.OnClose(func(e *mygo.CloseEvent) {
		once.Do(func() {
			if onClose != nil {
				onClose()
			}
			close(p.closed)
		})
	})
	// Activate the app first: a new window created while the app is in the
	// background can open behind other apps, which looks like nothing happened.
	mygo.App.Focus()
	win.Show()
	win.Focus()

	select {
	case <-done:
		win.Close()
	case <-p.closed:
		// The user closed the window.
	case <-ctx.Done():
		win.Close()
	}
	return nil
}
