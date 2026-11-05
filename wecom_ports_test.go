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

// lsof 的端口在倒数第二列（最后是 "(LISTEN)"），取第八列只会拿到 "TCP"。
func TestLsofWeComPorts(t *testing.T) {
	out := `COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
WeCom       796   a1  182u  IPv4 0x4960a4b8938da52b      0t0  TCP 127.0.0.1:50011 (LISTEN)
WeCom       796   a1  183u  IPv6 0x461377cde80cd4b7      0t0  TCP [::1]:50018 (LISTEN)
rapportd    669   a1    8u  IPv4 0x1bbd2f7c531651fc      0t0  TCP *:49161 (LISTEN)`
	got := lsofWeComPorts(out)
	want := []int{50011, 50018}
	if len(got) != len(want) {
		t.Fatalf("lsofWeComPorts = %v，想要 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lsofWeComPorts = %v，想要 %v", got, want)
		}
	}
}

// 客户端被挤走后换的端口，要排在其它内部服务前面才找得快。
func TestOrderDiscovered(t *testing.T) {
	got := orderDiscovered([]int{9882, 50018, 55161, 50010, 50001})
	want := []int{50010, 50001, 9882, 50018, 55161}
	if len(got) != len(want) {
		t.Fatalf("orderDiscovered = %v，想要 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orderDiscovered = %v，想要 %v", got, want)
		}
	}
}
