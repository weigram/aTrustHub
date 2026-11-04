package cdp

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestPauseRequestsCapturesURL checks the plumbing the single sign-on login
// depends on: a matching request must be held and its address readable before
// it reaches the server.
func TestPauseRequestsCapturesURL(t *testing.T) {
	raw := os.Getenv("CDP_PORT")
	if raw == "" {
		t.Skip("设置 CDP_PORT 指向一个开了远程调试端口的 Chrome 才会运行")
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("CDP_PORT=%q 不是端口", raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := Attach(ctx, port)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer client.Close()
	if err := client.Enable(ctx); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	got := make(chan string, 1)
	client.OnEvent(func(method string, params json.RawMessage) {
		if method != "Fetch.requestPaused" {
			return
		}
		var ev struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if json.Unmarshal(params, &ev) != nil {
			return
		}
		drop, dropCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = client.DropRequest(drop, ev.RequestID)
		dropCancel()
		select {
		case got <- ev.Request.URL:
		default:
		}
	})
	if err := client.PauseRequests(ctx, "*www.baidu.com*"); err != nil {
		t.Fatalf("PauseRequests: %v", err)
	}
	if err := client.Navigate(ctx, "https://www.baidu.com/robots.txt"); err != nil {
		t.Fatalf("Navigate: %v", err)
	}
	select {
	case url := <-got:
		if url == "" {
			t.Fatal("拦截到的地址为空")
		}
	case <-ctx.Done():
		t.Fatal("请求没有被拦下")
	}
}
