//go:build !windows

package main

import "os/exec"

// newCmd builds a command; outside Windows there is no console window to hide.
func newCmd(name string, args ...string) *exec.Cmd { return exec.Command(name, args...) }
