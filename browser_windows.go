//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// chromiumBrowsers lists the Windows browser executables that accept
// --proxy-server, in order of preference.
func chromiumBrowsersList() []string {
	var out []string
	for _, env := range []string{"PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		out = append(out,
			filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`),
		)
	}
	return out
}

var chromiumBrowsers = chromiumBrowsersList()
