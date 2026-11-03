//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// newCmd builds a command that never flashes a console window.
func newCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(systemPath(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

// systemPath resolves a bare command to its file under the Windows system
// directory: the helper can be started with a PATH that has no System32 in it,
// and then "powershell" or "netsh" cannot be found at all.
func systemPath(name string) string {
	if strings.ContainsAny(name, `/\`) {
		return name
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	exe := name
	if !strings.HasSuffix(strings.ToLower(exe), ".exe") {
		exe += ".exe"
	}
	for _, dir := range []string{
		filepath.Join(root, "System32"),
		filepath.Join(root, "System32", "WindowsPowerShell", "v1.0"),
		filepath.Join(root, "Sysnative"),
	} {
		path := filepath.Join(dir, exe)
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return name
}
