//go:build windows

package main

import (
	"fmt"
	"strings"
)

// proxyKey is the WinINET settings key every Windows app reads.
const proxyKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// applySystemProxy turns the Windows system proxy (WinINET) on or off,
// pointing it at hostPort. No elevation is needed: the setting lives in the
// current user's registry.
func applySystemProxy(hostPort string, on bool) error {
	host, port, ok := strings.Cut(hostPort, ":")
	if !ok || host == "" || port == "" {
		return fmt.Errorf("代理地址无效：%s", hostPort)
	}
	if on {
		// WinINET takes a SOCKS entry as "socks=host:port".
		if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyServer",
			"/t", "REG_SZ", "/d", "socks="+hostPort, "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("写代理地址失败：%v：%s", err, strings.TrimSpace(string(out)))
		}
		if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyOverride",
			"/t", "REG_SZ", "/d", "<local>", "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("写代理例外失败：%v：%s", err, strings.TrimSpace(string(out)))
		}
	}
	value := "0"
	if on {
		value = "1"
	}
	if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyEnable",
		"/t", "REG_DWORD", "/d", value, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("切换代理开关失败：%v：%s", err, strings.TrimSpace(string(out)))
	}
	notifyProxyChanged()
	return nil
}

// systemProxyEnabled reports whether WinINET currently has a proxy enabled.
func systemProxyEnabled() bool {
	out, err := newCmd("reg", "query", proxyKey, "/v", "ProxyEnable").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "0x1")
}

// notifyProxyChanged tells running applications to re-read the settings.
func notifyProxyChanged() {
	const script = `
$sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'
$t = Add-Type -MemberDefinition $sig -Name WinINet -Namespace Native -PassThru
[void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
`
	_ = newCmd("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Run()
}

// applySystemProxyFn is the seam tests use, so a unit test never rewrites the
// machine's real proxy settings.
var applySystemProxyFn = applySystemProxy
