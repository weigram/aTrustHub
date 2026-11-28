package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/qy/easyconnect/internal/vpn"
)

// clashPoint is one access point reduced to what the rules need.
type clashPoint struct {
	Name      string
	SocksPort int
	Online    bool
	Apps      []vpn.App
}

// clashRuleGroup is one application's rules, kept with the comment lines the
// human-readable output prints above them.
type clashRuleGroup struct {
	Point string
	App   string
	Rules []string
}

// clashPlan is the shared result both output formats render from.
type clashPlan struct {
	Points  []clashPoint
	Groups  []clashRuleGroup
	Rules   int
	NoProxy []string
	Offline []string
}

// buildClashPlan filters the points and turns every application address into
// rules, once, so the two output formats cannot drift apart.
func buildClashPlan(points []clashPoint) clashPlan {
	var plan clashPlan
	for _, p := range points {
		if !p.Online {
			plan.Offline = append(plan.Offline, p.Name)
			continue
		}
		if p.SocksPort <= 0 {
			plan.NoProxy = append(plan.NoProxy, p.Name)
			continue
		}
		plan.Points = append(plan.Points, p)
	}
	plan.Points = append([]clashPoint(nil), plan.Points...)
	sort.Strings(plan.NoProxy)
	sort.Strings(plan.Offline)
	sort.SliceStable(plan.Points, func(i, j int) bool { return plan.Points[i].Name < plan.Points[j].Name })

	seen := map[string]bool{}
	for _, p := range plan.Points {
		group := clashGroupName(p.Name)
		for _, app := range p.Apps {
			var rules []string
			for _, addr := range app.Addresses {
				rules = append(rules, clashRulesForAddress(addr.Host, addr.Port, group)...)
			}
			if len(rules) == 0 {
				rules = append(rules, clashRulesForAddress(app.AppAddress, "", group)...)
			}
			var fresh []string
			for _, r := range rules {
				base := strings.TrimSpace(strings.SplitN(r, "  #", 2)[0])
				if seen[base] {
					continue
				}
				seen[base] = true
				fresh = append(fresh, r)
			}
			if len(fresh) == 0 {
				continue
			}
			plan.Groups = append(plan.Groups, clashRuleGroup{Point: p.Name, App: app.Name, Rules: fresh})
			plan.Rules += len(fresh)
		}
	}
	return plan
}

// clashSkippedNote says which access points produced no rules, and why, in one
// line. Empty when every point contributed.
func clashSkippedNote(plan clashPlan) string {
	var items []string
	for _, name := range plan.Offline {
		items = append(items, name+"（未登录）")
	}
	for _, name := range plan.NoProxy {
		items = append(items, name+"（无独立 SOCKS5 端口）")
	}
	if len(items) == 0 {
		return ""
	}
	return "以下接入点未生成：" + strings.Join(items, "、")
}

// generateClashMerge renders the same plan as Clash Verge's "global extension"
// (Merge) keys, so it can be pasted straight into that dialog.
func generateClashMerge(points []clashPoint) string {
	plan := buildClashPlan(points)
	var b strings.Builder
	b.WriteString("# ===== aTrust Hub 分流规则（Clash Verge 扩展配置格式）=====\n")
	b.WriteString("# 粘贴到 Clash Verge -> 配置 -> 全局扩展覆写配置（Merge）里，保存后重新应用。\n")
	b.WriteString("# prepend-* 让这些规则排在订阅自带规则之前。\n\n")

	b.WriteString("prepend-proxies:\n")
	if len(plan.Points) == 0 {
		b.WriteString("  []\n")
	}
	for _, p := range plan.Points {
		fmt.Fprintf(&b, "  - name: %q\n", clashName(p.Name))
		b.WriteString("    type: socks5\n")
		b.WriteString("    server: 127.0.0.1\n")
		fmt.Fprintf(&b, "    port: %d\n", p.SocksPort)
		b.WriteString("    udp: false\n")
	}
	b.WriteString("\n")

	b.WriteString("prepend-proxy-groups:\n")
	if len(plan.Points) == 0 {
		b.WriteString("  []\n")
	}
	for _, p := range plan.Points {
		fmt.Fprintf(&b, "  - name: %q\n", clashGroupName(p.Name))
		b.WriteString("    type: select\n")
		fmt.Fprintf(&b, "    proxies: [%q]\n", clashName(p.Name))
	}
	b.WriteString("\n")

	b.WriteString("prepend-rules:\n")
	if plan.Rules == 0 {
		b.WriteString("  []\n")
	}
	lastPoint := ""
	for _, g := range plan.Groups {
		if g.Point != lastPoint {
			fmt.Fprintf(&b, "  # %s\n", g.Point)
			lastPoint = g.Point
		}
		fmt.Fprintf(&b, "  #   %s\n", g.App)
		for _, r := range g.Rules {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}
	return b.String()
}


// clashName is the proxy name for a point. Quotes and commas would break the
// YAML/rule syntax, so they are replaced.
func clashName(point string) string {
	return "aTrust-" + sanitizeClashName(point)
}

// clashGroupName is the policy group a point's rules point at.
func clashGroupName(point string) string {
	return "aTrust-" + sanitizeClashName(point) + "-组"
}

func sanitizeClashName(s string) string {
	s = strings.TrimSpace(s)
	r := strings.NewReplacer(`"`, "", `'`, "", ",", "-", "\n", " ", "\t", " ")
	s = r.Replace(s)
	if s == "" {
		return "未命名"
	}
	return s
}

// clashRulesForAddress turns one application address into Clash rules.
// Domains become DOMAIN-SUFFIX, IPs and CIDRs become IP-CIDR, and an IP range
// is expanded to the minimal set of CIDR blocks. Ports cannot be expressed on
// an IP-CIDR rule, so a narrow port is kept as a trailing comment.
func clashRulesForAddress(host, port string, group string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	// "host:port" may arrive in one field.
	if h, p, err := net.SplitHostPort(host); err == nil {
		host, port = h, p
	}
	note := ""
	if port != "" && port != "1-65535" && port != "0-65535" {
		note = "  # 端口 " + port
	}

	var prefixes []string
	switch {
	case strings.Contains(host, "/"):
		if _, _, err := net.ParseCIDR(host); err == nil {
			prefixes = []string{host}
		}
	case strings.Contains(host, "-"):
		prefixes = cidrsForRange(host)
	case net.ParseIP(host) != nil:
		prefixes = []string{host + "/32"}
	default:
		// A name: suffix matching covers the host and its subdomains.
		if !strings.Contains(host, ".") {
			return nil
		}
		return []string{fmt.Sprintf("DOMAIN-SUFFIX,%s,%s%s", host, group, note)}
	}
	if len(prefixes) == 0 {
		return nil
	}
	rules := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		rules = append(rules, fmt.Sprintf("IP-CIDR,%s,%s,no-resolve%s", p, group, note))
	}
	return rules
}

// cidrsForRange turns "a.b.c.d-a.b.c.e" into the minimal covering CIDR list.
func cidrsForRange(host string) []string {
	i := strings.Index(host, "-")
	if i <= 0 {
		return nil
	}
	lo := net.ParseIP(strings.TrimSpace(host[:i])).To4()
	hi := net.ParseIP(strings.TrimSpace(host[i+1:])).To4()
	if lo == nil || hi == nil {
		return nil
	}
	a := uint64(binary.BigEndian.Uint32(lo))
	b := uint64(binary.BigEndian.Uint32(hi))
	if a > b {
		a, b = b, a
	}
	var out []string
	for a <= b {
		// Largest block that fits: smaller prefix = bigger block, so scan the
		// prefix length upward and take the first one aligned and inside range.
		bits := 32
		for p := 0; p <= 32; p++ {
			size := uint64(1) << uint(32-p)
			if a%size == 0 && a+size-1 <= b {
				bits = p
				break
			}
		}
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(a))
		out = append(out, fmt.Sprintf("%s/%d", net.IP(buf[:]).String(), bits))
		size := uint64(1) << uint(32-bits)
		if a+size-1 >= b {
			break
		}
		a += size
		if len(out) >= 512 {
			break
		}
	}
	return out
}