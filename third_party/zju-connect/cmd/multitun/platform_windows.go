//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// setSystemDNS points every interface's IPv4 DNS at addr.
func setSystemDNS(addr string) {
	_ = exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses %s", addr)).Run()
}

// restoreSystemDNS hands DNS back to DHCP.
func restoreSystemDNS() {
	_ = exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ResetServerAddresses").Run()
}

// systemDNSIs reports whether every interface already uses addr.
func systemDNSIs(addr string) bool {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses").Output()
	if err != nil {
		return false
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, addr) {
			return false
		}
	}
	return true
}

// cleanupLegacyHosts has nothing to undo on Windows.
func cleanupLegacyHosts() {}

// processAlive asks tasklist about pid; a missing process means not alive.
func processAlive(pid int) bool {
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), fmt.Sprintf("%d", pid))
}

// terminateProcess force-stops pid.
func terminateProcess(pid int) {
	_ = exec.Command("taskkill", "/PID", fmt.Sprintf("%d", pid), "/F").Run()
}
