//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// supportsSystemProxy reports whether the system proxy can be set here.
func supportsSystemProxy() bool { return true }

// supportsElevatedTUN reports whether TUN can be started.
func supportsElevatedTUN() bool { return true }

// tunTaskName is the scheduled task that runs the helper elevated, so later
// starts need no UAC prompt.
const tunTaskName = "aTrustHubTUN"

// taskMarker records the command line the task was created with.
func taskMarker(dir string) string { return filepath.Join(dir, "tun-task.txt") }

// startHelper runs the helper through the scheduled task: one UAC prompt the
// first time, none afterwards.
func startHelper(helper string, args []string, launchLog string) error {
	if err := exec.Command("schtasks", "/Query", "/TN", tunTaskName).Run(); err != nil {
		return fmt.Errorf("计划任务未安装：%w", err)
	}
	out, err := exec.Command("schtasks", "/Run", "/TN", tunTaskName).CombinedOutput()
	_ = os.WriteFile(launchLog, out, 0o644)
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureHelperPrivilege registers the elevated scheduled task once, so later
// starts need no UAC prompt. schtasks caps its /TR argument at 261 characters,
// which our command line exceeds, so the task is registered from PowerShell.
func (a *app) ensureHelperPrivilege(helper string, args []string) error {
	cmdline := buildCommandLine(helper, args)
	marker := taskMarker(a.dir)
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == cmdline {
		if exec.Command("schtasks", "/Query", "/TN", tunTaskName).Run() == nil {
			return nil
		}
	}

	// The script quotes everything once; PowerShell registers it elevated.
	ps1 := filepath.Join(a.dir, "tun-task.ps1")
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute '%s' -Argument '%s'
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName '%s' -Action $action -Principal $principal -Force | Out-Null
`,
		strings.ReplaceAll(helper, "'", "''"),
		strings.ReplaceAll(buildArgumentLine(args), "'", "''"),
		tunTaskName)
	if err := os.WriteFile(ps1, []byte(script), 0o644); err != nil {
		return err
	}
	// Start-Process joins its -ArgumentList with spaces without quoting, so
	// the whole inner command line is one string with the path in quotes.
	inner := fmt.Sprintf(`-NoProfile -ExecutionPolicy Bypass -File "%s"`, ps1)
	outer := fmt.Sprintf(
		`$p = Start-Process -FilePath powershell -ArgumentList '%s' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode`,
		strings.ReplaceAll(inner, "'", "''"))
	out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", outer).CombinedOutput()
	taskLog := filepath.Join(a.dir, "tun-task.log")
	_ = os.WriteFile(taskLog, []byte(outer+"\n---\n"+string(out)), 0o644)
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	if exec.Command("schtasks", "/Query", "/TN", tunTaskName).Run() != nil {
		return fmt.Errorf("计划任务未创建成功")
	}
	_ = os.WriteFile(marker, []byte(cmdline+"\n"), 0o600)
	return nil
}

// startHelperElevated runs the helper directly with a UAC prompt, used when
// the scheduled task is unavailable.
func startHelperElevated(helper string, args []string, launchLog string) error {
	inner := fmt.Sprintf(`-FilePath "%s" -ArgumentList '%s' -Verb RunAs -WindowStyle Hidden`,
		strings.ReplaceAll(helper, `"`, `""`),
		strings.ReplaceAll(buildArgumentLine(args), "'", "''"))
	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", inner)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(launchLog, out, 0o644)
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// buildArgumentLine quotes only the arguments, for New-ScheduledTaskAction.
func buildArgumentLine(args []string) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, `"`+a+`"`)
	}
	return strings.Join(parts, " ")
}

// buildCommandLine quotes the helper call the way schtasks expects.
func buildCommandLine(helper string, args []string) string {
	parts := []string{`"` + helper + `"`}
	for _, a := range args {
		parts = append(parts, `"`+a+`"`)
	}
	return strings.Join(parts, " ")
}

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

// terminateHelper force-stops the TUN helper by pid. It runs elevated, so the
// kill needs the same elevation.
func terminateHelper(pid int) error {
	if pid <= 0 {
		return nil
	}
	ps := fmt.Sprintf(
		"Start-Process -FilePath taskkill -ArgumentList '/PID','%d','/F' -Verb RunAs -Wait -WindowStyle Hidden", pid)
	if out, err := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps).CombinedOutput(); err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// helperAlive reports whether the helper process still exists.
func helperAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, err := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), fmt.Sprintf("%d", pid))
}
