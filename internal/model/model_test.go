package model

import "testing"

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
