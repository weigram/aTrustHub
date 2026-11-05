package main

import (
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// wecomDesktopPorts returns the local ports a running desktop WeCom actually
// listens on, followed by the well-known ones.
//
// 固定端口列表在不同平台上并不一致（Windows 客户端与 mac 用的端口就不同），
// 所以先问系统「微信在听哪些端口」，再退回已知端口。
func wecomDesktopPorts(known []int) []int {
	out := make([]int, 0, len(known)+4)
	seen := map[int]bool{}
	add := func(p int) {
		if p <= 0 || p > 65535 || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	found := discoverWeComPorts()
	if len(found) > 0 {
		wecomLogf("发现电脑企业微信监听端口：%v", found)
	} else {
		wecomLogf("系统里没有发现企业微信的监听端口（客户端可能没安装或没启动）")
	}
	for _, p := range found {
		add(p)
	}
	for _, p := range known {
		add(p)
	}
	return out
}

// discoverWeComPorts lists listening ports owned by a WeCom process.
func discoverWeComPorts() []int {
	switch runtime.GOOS {
	case "windows":
		return windowsWeComPorts()
	case "darwin", "linux":
		return unixWeComPorts()
	}
	return nil
}

// windowsWeComPorts joins netstat and tasklist: the client's process name is
// WXWork.exe (企业微信桌面版).
func windowsWeComPorts() []int {
	names := []string{"wxwork.exe", "wecom.exe", "wxworkweb.exe"}
	cmd := newCmd("tasklist", "/FO", "CSV", "/NH")
	raw, err := cmd.Output()
	if err != nil {
		return nil
	}
	pids := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ",")
		if len(fields) < 2 {
			continue
		}
		image := strings.ToLower(strings.Trim(fields[0], `"`))
		for _, want := range names {
			if image == want {
				pids[strings.Trim(fields[1], `"`)] = true
			}
		}
	}
	if len(pids) == 0 {
		return nil
	}

	cmd = newCmd("netstat", "-ano", "-p", "TCP")
	raw, err = cmd.Output()
	if err != nil {
		return nil
	}
	ports := make([]int, 0, 8)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		if !pids[fields[4]] {
			continue
		}
		addr := fields[1]
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			if p, err := strconv.Atoi(addr[i+1:]); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// unixWeComPorts asks lsof for the desktop client's listening sockets.
func unixWeComPorts() []int {
	cmd := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
	raw, err := cmd.Output()
	if err != nil {
		return nil
	}
	return lsofWeComPorts(string(raw))
}

// lsofWeComPorts keeps the listening sockets of the desktop client.
//
// lsof prints COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME, so the
// address with the port is the second-to-last field, not the eighth: the
// eighth is the NODE column ("TCP"), which is why reading it never found a
// port at all.
func lsofWeComPorts(out string) []int {
	ports := make([]int, 0, 8)
	for _, line := range strings.Split(out, "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "wecom") && !strings.Contains(lower, "wxwork") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		name := fields[len(fields)-1]
		if strings.HasPrefix(name, "(") { // "(LISTEN)"
			if len(fields) < 10 {
				continue
			}
			name = fields[len(fields)-2]
		}
		if i := strings.LastIndex(name, ":"); i >= 0 {
			if p, err := strconv.Atoi(name[i+1:]); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// orderDiscovered puts the ports the client is known to prefer first and the
// rest after it. When the preferred port was taken and the client moved, the
// new port is then tried right after the old one instead of behind every
// internal service the client also listens on.
func orderDiscovered(ports []int) []int {
	rank := func(p int) int {
		switch {
		case p >= 50010 && p <= 50013:
			return 0
		case p >= 50000 && p <= 50002:
			return 1
		default:
			return 2
		}
	}
	// Equal ranks keep the order the system listed them in: it is the only
	// ordering that carries information, and guesses are not worth it.
	sort.SliceStable(ports, func(i, j int) bool {
		return rank(ports[i]) < rank(ports[j])
	})
	return ports
}
