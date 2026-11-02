//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// newCmd builds a command that never flashes a console window.
func newCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}
