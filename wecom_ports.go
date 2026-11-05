package main

import (
	"os/exec"
	"runtime"
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
	ports := make([]int, 0, 8)
	for _, line := range strings.Split(string(raw), "\n") {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "wecom") && !strings.Contains(lower, "wxwork") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		addr := fields[8]
		if i := strings.LastIndex(addr, ":"); i >= 0 {
			if p, err := strconv.Atoi(addr[i+1:]); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}
