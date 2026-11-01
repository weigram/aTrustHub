package main

import (
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/vpn"
)

func TestAppOpenURL(t *testing.T) {
	app := vpn.App{AccessEntry: "https://portal.example/app"}
	if got := appOpenURL(app); got != "https://portal.example/app" {
		t.Errorf("access entry = %q", got)
	}
	app = vpn.App{Addresses: []vpn.AppAddress{{Protocol: "all", Host: "app.example.com", Port: "443"}}}
	if got := appOpenURL(app); got != "https://app.example.com/" {
		t.Errorf("host url = %q", got)
	}
	if got := appOpenURL(vpn.App{}); got != "" {
		t.Errorf("empty = %q", got)
	}
}

func TestProxyBrowserCommand(t *testing.T) {
	cmd := proxyBrowserCommand("127.0.0.1:10880", "https://app.example.com/")
	if !strings.Contains(cmd, "--proxy-server=socks5://127.0.0.1:10880") {
		t.Errorf("command lacks proxy: %s", cmd)
	}
	if !strings.Contains(cmd, "https://app.example.com/") {
		t.Errorf("command lacks url: %s", cmd)
	}
}
