package model

import (
	"strings"
	"testing"
)

func TestSetAppDisabled(t *testing.T) {
	p := &AccessPoint{ID: "p1"}
	if p.AppDisabled("a") {
		t.Fatal("默认应为启用")
	}
	if !p.SetAppDisabled("a", true) {
		t.Fatal("首次停用应报告变化")
	}
	if p.SetAppDisabled("a", true) {
		t.Fatal("重复停用不应报告变化")
	}
	if !p.AppDisabled("a") || p.AppDisabled("b") {
		t.Fatal("停用状态不对")
	}
	if !p.SetAppDisabled("a", false) {
		t.Fatal("恢复应报告变化")
	}
	if p.AppDisabled("a") {
		t.Fatal("恢复后仍被记为停用")
	}
	if len(p.DisabledApps) != 0 {
		t.Fatalf("恢复后列表应为空，实际 %v", p.DisabledApps)
	}
	if p.SetAppDisabled("", true) {
		t.Fatal("空 ID 不应改变状态")
	}
}

func TestMonitorDefaults(t *testing.T) {
	p := &AccessPoint{ID: "p1"}
	if !p.MonitorEnabled() {
		t.Fatal("未设置时应默认开启监测")
	}
	if p.MonitorIntervalSeconds() != 300 {
		t.Fatalf("默认间隔应为 300 秒，实际 %d", p.MonitorIntervalSeconds())
	}
	off := false
	p.Monitor = &off
	if p.MonitorEnabled() {
		t.Fatal("显式关闭后不应开启")
	}
	p.MonitorInterval = 5
	if got := p.MonitorIntervalSeconds(); got != 30 {
		t.Fatalf("间隔应有下限，实际 %d", got)
	}
	p.MonitorInterval = 900
	if got := p.MonitorIntervalSeconds(); got != 900 {
		t.Fatalf("应保留用户设置，实际 %d", got)
	}
}

// 认证方式下拉里不再提供「自动识别」：登录流程由配置决定。
func TestAuthModeLabelsDropAuto(t *testing.T) {
	var labels []string
	for _, entry := range AuthModeLabels {
		labels = append(labels, entry.Label)
		if entry.Value == AuthModeAuto {
			t.Fatal("自动识别 不应再出现在可选认证方式里")
		}
	}
	want := []string{"账号密码", "企业微信", "单点登录"}
	if strings.Join(labels, "|") != strings.Join(want, "|") {
		t.Fatalf("labels = %v, want %v", labels, want)
	}
	if !AuthModeSSO.Valid() {
		t.Fatal("单点登录 should be a valid mode")
	}
}

// 老配置里的 auto 仍然可用，避免升级后原本能登的接入点被改坏。
func TestLegacyAutoStaysValid(t *testing.T) {
	if !AuthModeAuto.Valid() {
		t.Fatal("auto should stay valid for old configurations")
	}
	p := &AccessPoint{Server: "vpn.example.edu.cn", AuthMode: string(AuthModeAuto)}
	p.Normalize()
	if p.AuthMode != string(AuthModeAuto) {
		t.Fatalf("auto was rewritten to %q", p.AuthMode)
	}
}

// 空认证方式一直是「账号密码」，现在自动识别没了，默认值必须落到密码上。
func TestNormalizeDefaultsToPassword(t *testing.T) {
	p := &AccessPoint{Server: "vpn.example.edu.cn", AuthMode: ""}
	p.Normalize()
	if p.AuthMode != string(AuthModePassword) {
		t.Fatalf("auth mode = %q, want psw", p.AuthMode)
	}
}
