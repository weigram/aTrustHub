package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/cdp"
)

// TestLaunchBrowserOpensDevToolsPort checks the part that broke in practice:
// the browser must actually listen on the DevTools port, which fails when an
// instance already holds the profile. It needs Chrome and is opt-in.
func TestLaunchBrowserOpensDevToolsPort(t *testing.T) {
	if os.Getenv("HUB_BROWSER_TEST") == "" {
		t.Skip("设置 HUB_BROWSER_TEST=1 才会启动浏览器")
	}
	exe := browserExecutable()
	if exe == "" {
		t.Skip("没有安装 Chrome/Edge")
	}
	profile := t.TempDir()
	port, err := cdp.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	proc, err := launchBrowser(exe, profile, port, "about:blank")
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer proc.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client, err := attachWhenReady(ctx, port, "")
	if err != nil {
		t.Fatalf("调试端口没有打开：%v", err)
	}
	defer client.Close()
	if err := client.Enable(ctx); err != nil {
		t.Fatalf("Enable: %v", err)
	}
}

// TestCloseLoginBrowserStopsIt checks that the browser is stopped and its state
// cleared once the session has been taken from it.
func TestCloseLoginBrowserStopsIt(t *testing.T) {
	dir := t.TempDir()
	// 一个我们真正拥有的进程，代替浏览器。
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skip("没有 sleep 命令")
	}
	writeBrowserState(dir, "p1", browserState{PID: cmd.Process.Pid, Port: 1234})

	closeLoginBrowser(dir, "p1")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("进程没有被结束")
	}
	if _, ok := readBrowserState(dir, "p1"); ok {
		t.Fatal("状态文件应当被清除")
	}
}
