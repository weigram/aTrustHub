//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// supportsSystemProxy reports whether the system proxy can be set here.
func supportsSystemProxy() bool { return true }

// supportsElevatedTUN reports whether TUN can be started with one prompt.
func supportsElevatedTUN() bool { return true }

// helperCommand builds the command that runs the TUN helper as root.
func helperCommand(helper string, args []string, logFile *os.File) (*exec.Cmd, error) {
	cmd := exec.Command("sudo", append([]string{"-n", helper}, args...)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return cmd, nil
}

// ensureHelperPrivilege installs the password-free sudoers rule once.
func (a *app) ensureHelperPrivilege(helper string) error {
	const rulePath = "/etc/sudoers.d/atrust-hub"
	marker := filepath.Join(a.dir, "sudoers-helper.txt")
	if _, err := os.Stat(rulePath); err == nil {
		if b, rerr := os.ReadFile(marker); rerr == nil && strings.TrimSpace(string(b)) == helper {
			return nil
		}
	}
	user := os.Getenv("USER")
	if user == "" {
		return fmt.Errorf("找不到当前用户")
	}
	rulePathInRule := strings.ReplaceAll(helper, " ", `\ `)
	rule := fmt.Sprintf("%s ALL=(root) NOPASSWD: %s\n", user, rulePathInRule)
	tmp, err := os.CreateTemp("", "atrust-sudoers-*")
	if err != nil {
		return err
	}
	path := tmp.Name()
	defer os.Remove(path)
	if _, err := tmp.WriteString(rule); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	_ = os.Chmod(path, 0o600)
	script := fmt.Sprintf("mkdir -p /etc/sudoers.d && cp %s %s && chmod 440 %s", shQuote(path), rulePath, rulePath)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "osascript", "-e",
		fmt.Sprintf(`do shell script "%s" with administrator privileges`, strings.ReplaceAll(script, `"`, `\"`)))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(rulePath); err != nil {
		return fmt.Errorf("免密规则未写入")
	}
	_ = os.WriteFile(marker, []byte(helper+"\n"), 0o600)
	return nil
}

// cleanupStaleDNS restores the system DNS when a previous run left it at the
// helper's resolver and the helper is gone.
func (a *app) cleanupStaleDNS() {
	services, err := networkServices()
	if err != nil {
		return
	}
	for _, svc := range services {
		out, err := exec.Command("networksetup", "-getdnsservers", svc).Output()
		if err != nil {
			continue
		}
		if strings.Contains(string(out), "127.0.0.1") {
			_ = exec.Command("networksetup", "-setdnsservers", svc, "Empty").Run()
			a.tunLogf("启动清理：已恢复 %s 的 DNS", svc)
		}
	}
}

// terminateHelper force-stops the TUN helper by pid.
func terminateHelper(pid int) error {
	if pid <= 0 {
		return nil
	}
	out, err := exec.Command("sudo", "-n", "kill", "-TERM", strconv.Itoa(pid)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v：%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// helperAlive reports whether the helper process still exists.
func helperAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
