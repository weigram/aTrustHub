package main

import (
	"strconv"
	"testing"
)

// 端口列表要「发现的在前、已知的在后」，且不能重复——重复发请求会拖慢检测。
func TestWecomDesktopPortsOrder(t *testing.T) {
	got := wecomDesktopPorts([]int{50010, 50010, 50011})
	seen := map[int]bool{}
	for _, p := range got {
		if seen[p] {
			t.Fatalf("端口重复：%v", got)
		}
		seen[p] = true
		if p <= 0 || p > 65535 {
			t.Fatalf("端口越界：%d", p)
		}
	}
	for _, want := range []int{50010, 50011} {
		if !seen[want] {
			t.Errorf("缺少已知端口 %s：%v", strconv.Itoa(want), got)
		}
	}
}
