//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// supportsSystemProxy reports whether the system proxy can be set here.
func supportsSystemProxy() bool { return true }

// supportsElevatedTUN reports whether TUN can be started.
func supportsElevatedTUN() bool { return true }

// helperCommand builds the command that runs the TUN helper as administrator.
// Windows shows a UAC prompt for the elevated process. Every argument is
// quoted, because the data directory usually contains a space
// ("AppData\Roaming\aTrust Hub").
func helperCommand(helper string, args []string, logFile *os.File) (*exec.Cmd, error) {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, `"`+strings.ReplaceAll(a, `"`, `""`)+`"`)
	}
	argLine := strings.ReplaceAll(strings.Join(quoted, " "), "'", "''")
	ps := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
try {
  $p = Start-Process -FilePath "%s" -ArgumentList '%s' -Verb RunAs -PassThru -WindowStyle Hidden
  Write-Output ("started " + $p.Id)
} catch {
  Write-Output ("error " + $_.Exception.Message)
  exit 1
}`, strings.ReplaceAll(helper, `"`, `""`), argLine)
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	return cmd, nil
}

// ensureHelperPrivilege has nothing to install on Windows: UAC asks once per
// start, which is handled by the elevated launch.
func (a *app) ensureHelperPrivilege(helper string) error { return nil }

// cleanupStaleDNS puts DNS back to DHCP when the helper is not running.
func (a *app) cleanupStaleDNS() {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses").Output()
	if err != nil {
		return
	}
	if strings.Contains(string(out), "127.0.0.1") {
		_ = exec.Command("powershell", "-NoProfile", "-Command",
			"Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ResetServerAddresses").Run()
		a.tunLogf("启动清理：已恢复系统 DNS")
	}
}
