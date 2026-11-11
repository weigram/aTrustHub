package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/vpn"
)

func TestCodePromptAsks(t *testing.T) {
	var got string
	p := &codePrompt{label: "短信验证码", hint: "验证码已发送到您的手机"}
	p.submit = func(code string) { got = code }

	tt := ui.NewTester(p.view, 420, 230)
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"短信验证码", "验证码已发送到您的手机"} {
		if !strings.Contains(texts, want) {
			t.Errorf("窗口缺少 %q；texts = %s", want, texts)
		}
	}
	tt.Type("654321")
	tt.Key(0, ui.KeyEnter)
	if got != "654321" {
		t.Fatalf("回车提交 = %q，想要 654321", got)
	}
}

func TestCodePromptRejectsEmpty(t *testing.T) {
	called := false
	p := &codePrompt{label: "短信验证码", hint: "提示"}
	p.submit = func(string) { called = true }

	tt := ui.NewTester(p.view, 420, 230)
	if err := tt.Click("确定"); err != nil {
		t.Fatalf("点确定：%v", err)
	}
	if called {
		t.Fatal("空验证码不该提交")
	}
	if !strings.Contains(strings.Join(tt.Texts(), "|"), "请输入验证码") {
		t.Errorf("没有提示空输入；texts = %s", strings.Join(tt.Texts(), "|"))
	}
	// 窗口还在，输入之后仍能提交。
	tt.Type("123456")
	tt.Key(0, ui.KeyEnter)
	if !called {
		t.Fatal("填了验证码之后应当能提交")
	}
}

func TestCodePromptText(t *testing.T) {
	label, hint := codePromptText(vpn.CodeRequest{Kind: vpn.CodeSMS, Tip: "已发送"})
	if label != "短信验证码" || !strings.HasPrefix(hint, "已发送") {
		t.Errorf("sms prompt = %q, %q", label, hint)
	}
	_, hint = codePromptText(vpn.CodeRequest{Kind: vpn.CodeSMS})
	if hint == "" {
		t.Error("sms prompt has no hint when the server said nothing")
	}
	label, hint = codePromptText(vpn.CodeRequest{Kind: vpn.CodeTOTP})
	if label != "动态口令" || hint != "请输入手机上的动态口令" {
		t.Errorf("totp prompt = %q, %q", label, hint)
	}
}
