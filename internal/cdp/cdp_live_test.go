package cdp

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLiveCookies talks to a browser started with a DevTools port. It runs only
// when REA_CDP_PORT is set, so an ordinary test run needs no browser.
func TestLiveCookies(t *testing.T) {
	raw := os.Getenv("CDP_PORT")
	if raw == "" {
		t.Skip("设置 CDP_PORT 指向一个开了远程调试端口的 Chrome 才会运行")
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("CDP_PORT=%q 不是端口", raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := Attach(ctx, port)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer client.Close()
	if err := client.Enable(ctx); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if err := client.Navigate(ctx, "https://zeroportal.cnyeig.net:8888/"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	time.Sleep(6 * time.Second)

	var href string
	if err := client.Evaluate(ctx, `location.href`, &href); err != nil {
		t.Logf("读地址失败：%v", err)
	}
	t.Logf("当前页面：%s", href)
	cookies, err := client.Cookies(ctx)
	if err != nil {
		t.Fatalf("Cookies: %v", err)
	}
	t.Logf("浏览器共有 %d 个 cookie", len(cookies))
	for _, c := range cookies {
		t.Logf("  %s %s", c.Domain, c.Name)
	}
	kept := CookiesFor(cookies, "zeroportal.cnyeig.net")
	if len(kept) == 0 {
		t.Fatal("没有取到该站点的 cookie")
	}
	names := make([]string, 0, len(kept))
	httpOnlySID := false
	for _, c := range kept {
		names = append(names, c.Name)
		if c.Name == "sid" && c.HTTPOnly && c.Value != "" {
			httpOnlySID = true
		}
	}
	if !httpOnlySID {
		t.Fatalf("没有取到 HttpOnly 的 sid，只有 %v", names)
	}
	// Device id lookup must not fail the flow when the portal keeps none.
	_ = browserDeviceIDProbe(ctx, client)
}

// browserDeviceIDProbe exercises the same evaluation the app runs.
func browserDeviceIDProbe(ctx context.Context, c *Client) string {
	var v string
	_ = c.Evaluate(ctx, `(function(){ try { return String(window.localStorage.length); } catch (e) { return ''; } })()`, &v)
	return strings.TrimSpace(v)
}
