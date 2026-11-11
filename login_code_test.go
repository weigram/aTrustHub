package main

import (
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/vpn"
)

func TestCodePromptHTML(t *testing.T) {
	page := codePromptHTML("短信验证码", "验证码已发送到您的手机 <183****5899>")
	for _, want := range []string{"短信验证码", "id=\"code\"", "确定"} {
		if !strings.Contains(page, want) {
			t.Errorf("page has no %q", want)
		}
	}
	if !strings.Contains(page, "183****5899&gt;") {
		t.Error("hint was not escaped")
	}
	if strings.Contains(page, "<183****5899>") {
		t.Error("hint kept its raw angle brackets")
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
