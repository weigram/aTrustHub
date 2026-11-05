//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// systemProxyEnabled reports whether the macOS system proxy is on. The app
// tracks its own switch, so this is only used to seed the UI.
func systemProxyEnabled() bool { return false }

// networkServices lists the enabled macOS network services, which system
// proxy settings are applied to.
func networkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		if strings.ContainsAny(line, "'\"\\") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

// applySystemProxy turns the macOS system SOCKS/HTTP/HTTPS proxy on or off
// for every enabled network service, pointing it at hostPort. It needs
// administrator rights, which macOS asks for once through osascript.
func applySystemProxy(hostPort string, on bool) error {
	host, port, ok := strings.Cut(hostPort, ":")
	if !ok || host == "" || port == "" {
		return fmt.Errorf("代理地址无效：%s", hostPort)
	}
	services, err := networkServices()
	if err != nil {
		return fmt.Errorf("读取网络服务失败：%w", err)
	}
	if len(services) == 0 {
		return fmt.Errorf("没有可设置的网络服务")
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	for _, svc := range services {
		if on {
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setwebproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxy '%s' %s %s\n", svc, host, port)
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxystate '%s' on\n", svc)
			fmt.Fprintf(&b, "networksetup -setwebproxystate '%s' on\n", svc)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxystate '%s' on\n", svc)
		} else {
			fmt.Fprintf(&b, "networksetup -setsocksfirewallproxystate '%s' off\n", svc)
			fmt.Fprintf(&b, "networksetup -setwebproxystate '%s' off\n", svc)
			fmt.Fprintf(&b, "networksetup -setsecurewebproxystate '%s' off\n", svc)
		}
	}
	f, err := os.CreateTemp("", "atrust-proxy-*.sh")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return err
	}
	f.Close()
	_ = os.Chmod(path, 0o700)

	script := fmt.Sprintf(`do shell script "/bin/sh %s" with administrator privileges`, path)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// applySystemProxyFn is the seam tests use: unit tests must never touch the
// real system settings (that would hang on a password prompt in CI).
var applySystemProxyFn = applySystemProxy
