//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

// redirectStderr points file descriptor 2 at f, so Go panics — which bypass
// the logging package — still land in a file we can read afterwards.
func redirectStderr(f *os.File) {
	_ = syscall.Dup2(int(f.Fd()), 2)
	os.Stderr = f
}
