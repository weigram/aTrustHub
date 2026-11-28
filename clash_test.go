package main

import (
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/vpn"
)

func TestClashRulesForAddress(t *testing.T) {
	cases := []struct {
		host, port string
		want       []string
	}{
		// 单个 IP → /32
		{"10.18.12.89", "1-65535", []string{"IP-CIDR,10.18.12.89/32,组,no-resolve"}},
		// CIDR 原样保留
		{"10.18.12.0/24", "", []string{"IP-CIDR,10.18.12.0/24,组,no-resolve"}},
		// 域名 → DOMAIN-SUFFIX
		{"oa.example", "443", []string{"DOMAIN-SUFFIX,oa.example,组  # 端口 443"}},
		// 单端口保留为注释
		{"10.0.0.1", "443", []string{"IP-CIDR,10.0.0.1/32,组,no-resolve  # 端口 443"}},
		// 没有点的名字不生成
		{"localhost", "", nil},
		{"", "", nil},
	}
	for _, c := range cases {
		got := clashRulesForAddress(c.host, c.port, "组")
		if len(got) != len(c.want) {
			t.Errorf("%s:%s → %v，想要 %v", c.host, c.port, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s:%s[%d] = %q，想要 %q", c.host, c.port, i, got[i], c.want[i])
			}
		}
	}
}

// IP 区间要拆成最少的 CIDR 块，且能被 net.ParseCIDR 接受。
func TestClashRulesForRange(t *testing.T) {
	rules := clashRulesForAddress("10.0.0.0-10.0.0.255", "", "组")
	if len(rules) != 1 {
		t.Fatalf("整段 /24 应合成 1 条，got %v", rules)
	}
	if rules[0] != "IP-CIDR,10.0.0.0/24,组,no-resolve" {
		t.Fatalf("rule = %q", rules[0])
	}

	rules = clashRulesForAddress("10.0.0.1-10.0.0.6", "", "组")
	if len(rules) < 2 {
		t.Fatalf("非对齐区间应拆多条，got %v", rules)
	}
	for _, r := range rules {
		parts := strings.Split(r, ",")
		if len(parts) < 2 || parts[0] != "IP-CIDR" {
			t.Fatalf("rule = %q", r)
		}
	}
}

// 输出只允许是 Clash Verge 的扩展配置格式：三个 prepend 键。
func TestGenerateClashMergeShape(t *testing.T) {
	out := generateClashMerge([]clashPoint{{
		Name: "清大科越access", SocksPort: 1081, Online: true,
		Apps: []vpn.App{
			{Name: "18F-同步通道", Addresses: []vpn.AppAddress{
				{Protocol: "tcp", Host: "10.18.12.89", Port: "1-65535"},
			}},
			{Name: "部门管理系统", Addresses: []vpn.AppAddress{
				{Protocol: "tcp", Host: "oa.example", Port: "443"},
			}},
		},
	}})

	for _, want := range []string{
		"prepend-proxies:",
		"prepend-proxy-groups:",
		"prepend-rules:",
		`- name: "aTrust-清大科越access"`,
		"type: socks5",
		"server: 127.0.0.1",
		"port: 1081",
		"udp: false",
		`proxies: ["aTrust-清大科越access"]`,
		"IP-CIDR,10.18.12.89/32,aTrust-清大科越access-组,no-resolve",
		"DOMAIN-SUFFIX,oa.example,aTrust-清大科越access-组",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少 %q\n---\n%s", want, out)
		}
	}
	// 普通格式的顶层键不能出现，否则会被 Clash Verge 当成未知字段。
	for _, unwanted := range []string{"\nproxies:", "\nproxy-groups:", "\nrules:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("不该含普通格式的 %q\n---\n%s", unwanted, out)
		}
	}
}

// 名字里的引号/逗号会破坏 YAML 与规则语法，必须被清掉。
func TestClashNameSanitize(t *testing.T) {
	out := generateClashMerge([]clashPoint{{Name: `a"b,c`, SocksPort: 1081, Online: true}})
	if strings.Contains(out, `"a"b`) {
		t.Errorf("名字没被清洗：\n%s", out)
	}
	if !strings.Contains(out, `- name: "aTrust-ab-c"`) {
		t.Errorf("清洗结果不对：\n%s", out)
	}
}

// 空输入也要产出结构完整、可直接粘贴的 YAML。
func TestGenerateClashMergeEmpty(t *testing.T) {
	out := generateClashMerge(nil)
	for _, want := range []string{"prepend-proxies:", "prepend-proxy-groups:", "prepend-rules:"} {
		if !strings.Contains(out, want) {
			t.Errorf("空配置缺少 %q", want)
		}
	}
	if strings.Count(out, "[") < 3 {
		t.Errorf("空配置应写成 []，got:\n%s", out)
	}
}

// 同一地址按 tcp/udp 重复出现时只保留一条规则。
func TestGenerateClashMergeDedupes(t *testing.T) {
	points := []clashPoint{{
		Name: "点", SocksPort: 1081, Online: true,
		Apps: []vpn.App{
			{Name: "a", Addresses: []vpn.AppAddress{
				{Protocol: "tcp", Host: "10.18.12.89", Port: "1-65535"},
				{Protocol: "udp", Host: "10.18.12.89", Port: "1-65535"},
			}},
		},
	}}
	out := generateClashMerge(points)
	if n := strings.Count(out, "IP-CIDR,10.18.12.89/32"); n != 1 {
		t.Fatalf("规则重复 %d 次：\n%s", n, out)
	}
	if plan := buildClashPlan(points); plan.Rules != 1 {
		t.Fatalf("plan.Rules = %d，想要 1", plan.Rules)
	}
}

// 未登录的接入点不能进规则：它的 SOCKS5 端口没在监听，规则指过去会失败。
func TestGenerateClashMergeSkipsOffline(t *testing.T) {
	points := []clashPoint{
		{Name: "在线点", SocksPort: 1081, Online: true,
			Apps: []vpn.App{{Name: "a", Addresses: []vpn.AppAddress{{Host: "10.0.0.1"}}}}},
		{Name: "离线点", SocksPort: 1082, Online: false},
		{Name: "无端口点", SocksPort: 0, Online: true},
	}
	out := generateClashMerge(points)
	if strings.Contains(out, "aTrust-离线点") {
		t.Fatalf("离线点不该出现在配置里：\n%s", out)
	}
	if strings.Contains(out, "aTrust-无端口点") {
		t.Fatalf("没有 SOCKS5 端口的点不该出现：\n%s", out)
	}
	if !strings.Contains(out, "aTrust-在线点") {
		t.Fatalf("在线点应该生成：\n%s", out)
	}
	plan := buildClashPlan(points)
	if len(plan.Offline) != 1 || plan.Offline[0] != "离线点" {
		t.Fatalf("Offline = %v", plan.Offline)
	}
	if len(plan.NoProxy) != 1 || plan.NoProxy[0] != "无端口点" {
		t.Fatalf("NoProxy = %v", plan.NoProxy)
	}
}

// 没有结构化地址时退回 AppAddress 字段，别丢掉应用。
func TestGenerateClashMergeUsesAppAddress(t *testing.T) {
	out := generateClashMerge([]clashPoint{{
		Name: "点", SocksPort: 1081, Online: true,
		Apps: []vpn.App{{Name: "单地址", AppAddress: "db.internal.example"}},
	}})
	if !strings.Contains(out, "DOMAIN-SUFFIX,db.internal.example,aTrust-点-组") {
		t.Fatalf("AppAddress 没被使用：\n%s", out)
	}
}
// 未生成的接入点要合成一句话说明原因。
func TestClashSkippedNote(t *testing.T) {
	plan := buildClashPlan([]clashPoint{
		{Name: "在线点", SocksPort: 1081, Online: true},
		{Name: "云能投", SocksPort: 1082, Online: false},
		{Name: "公司18L", SocksPort: 0, Online: true},
	})
	note := clashSkippedNote(plan)
	if !strings.HasPrefix(note, "以下接入点未生成：") {
		t.Fatalf("note = %q", note)
	}
	if !strings.Contains(note, "云能投（未登录）") {
		t.Errorf("缺少未登录原因：%q", note)
	}
	if !strings.Contains(note, "公司18L（无独立 SOCKS5 端口）") {
		t.Errorf("缺少无端口原因：%q", note)
	}
	if strings.Contains(note, "在线点") {
		t.Errorf("在线点不该出现在提示里：%q", note)
	}

	// 全部可用时没有提示。
	if got := clashSkippedNote(buildClashPlan([]clashPoint{
		{Name: "点", SocksPort: 1081, Online: true},
	})); got != "" {
		t.Fatalf("不该有提示：%q", got)
	}
}
