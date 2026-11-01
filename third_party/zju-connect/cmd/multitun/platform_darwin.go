//go:build darwin

package main

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
)

// setSystemDNS points every network service at addr.
func setSystemDNS(addr string) {
	for _, svc := range networkServices() {
		_ = exec.Command("networksetup", "-setdnsservers", svc, addr).Run()
	}
}

// restoreSystemDNS puts the services back to DHCP-provided DNS.
func restoreSystemDNS() {
	for _, svc := range networkServices() {
		_ = exec.Command("networksetup", "-setdnsservers", svc, "Empty").Run()
	}
}

// systemDNSIs reports whether every service already uses addr.
func systemDNSIs(addr string) bool {
	services := networkServices()
	if len(services) == 0 {
		return false
	}
	for _, svc := range services {
		out, err := exec.Command("networksetup", "-getdnsservers", svc).Output()
		if err != nil || !strings.Contains(string(out), addr) {
			return false
		}
	}
	return true
}

// networkServices lists enabled network services.
func networkServices() []string {
	out, err := exec.Command("/bin/sh", "-c", "networksetup -listallnetworkservices | tail -n +2").Output()
	if err != nil {
		return nil
	}
	var list []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		list = append(list, line)
	}
	return list
}

// cleanupLegacyHosts strips the pretend-IP block older builds wrote.
func cleanupLegacyHosts() {
	stripHostsBlock("/etc/hosts", "# >>> aTrust Hub TUN >>>", "# <<< aTrust Hub TUN <<<")
}

// processAlive reports whether pid exists. A process owned by another user
// answers EPERM, which still means alive.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// terminateProcess asks pid to stop.
func terminateProcess(pid int) {
	_ = syscall.Kill(pid, syscall.SIGTERM)
}
