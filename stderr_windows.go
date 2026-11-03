//go:build windows

package main

import (
	"os"
)

// redirectStderr keeps a panic record on platforms where reassigning os.Stderr
// is enough; Windows has no Dup2 in syscall, and a crash there is captured by
// the event log instead.
func redirectStderr(f *os.File) {
	os.Stderr = f
}
