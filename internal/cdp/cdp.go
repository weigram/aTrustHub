// Package cdp drives a Chromium browser over the Chrome DevTools Protocol.
//
// It exists for one reason: a browser owns the login session of an aTrust
// portal, including the HttpOnly cookies a WebView cannot read, so reading
// them from the browser is what lets the tunnel reuse a login performed by
// hand.
package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// Client is one attached page. One goroutine reads the socket and hands each
// message to the call waiting for it or to the event handler, so a paused
// request can be answered while another call is in flight.
type Client struct {
	conn *websocket.Conn

	mu      sync.Mutex
	nextID  int
	pending map[int]chan response
	events  func(method string, params json.RawMessage)
	closed  bool
}

type response struct {
	result json.RawMessage
	err    error
}

// Target is one debuggable page.
type Target struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	Title                string `json:"title"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// Cookie is a browser cookie, including HttpOnly ones.
type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HTTPOnly bool   `json:"httpOnly"`
}

// DebugURL is the DevTools HTTP endpoint of a browser on port.
func DebugURL(port int) string {
	return fmt.Sprintf("http://127.0.0.1:%d", port)
}

// List returns the pages the browser on port exposes.
func List(ctx context.Context, port int) ([]Target, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, DebugURL(port)+"/json/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var targets []Target
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// Attach connects to the page of the browser on port that is most likely the
// one being looked at.
func Attach(ctx context.Context, port int) (*Client, error) {
	return AttachFor(ctx, port, "")
}

// AttachFor prefers a page showing host: a login opens tabs, and attaching to
// a blank one would read an empty address forever.
func AttachFor(ctx context.Context, port int, host string) (*Client, error) {
	targets, err := List(ctx, port)
	if err != nil {
		return nil, err
	}
	// chrome:// 之类页面没有站点状态，附着上去只会读到空地址。
	var best *Target
	for i := range targets {
		t := &targets[i]
		if t.Type != "page" || t.WebSocketDebuggerURL == "" {
			continue
		}
		if best == nil {
			best = t
		}
		if host != "" && strings.Contains(t.URL, host) {
			best = t
			break
		}
		if best == t {
			continue
		}
		if strings.HasPrefix(t.URL, "http://") || strings.HasPrefix(t.URL, "https://") {
			best = t
		}
	}
	for _, t := range targets {
		if best == nil || t.WebSocketDebuggerURL != best.WebSocketDebuggerURL {
			continue
		}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, t.WebSocketDebuggerURL, nil)
		if err != nil {
			return nil, err
		}
		c := &Client{conn: conn, pending: map[int]chan response{}}
		go c.readLoop()
		return c, nil
	}
	return nil, errors.New("浏览器没有可用的页面")
}

// CloseBrowser asks the browser to shut itself down, which is how it flushes
// the profile: cookies and a password saved a moment ago land on disk only if
// the browser exits on its own terms.
func (c *Client) CloseBrowser(ctx context.Context) error {
	return c.call(ctx, "Browser.close", nil, nil)
}

// Close ends the connection, not the browser.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.conn.Close()
}

// call sends one command and returns its result.
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	ch := make(chan response, 1)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("调试连接已关闭")
	}
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()

	msg := map[string]any{"id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if err := c.conn.WriteJSON(msg); err != nil {
		c.drop(id)
		return err
	}
	select {
	case <-ctx.Done():
		c.drop(id)
		return ctx.Err()
	case res := <-ch:
		if res.err != nil {
			return fmt.Errorf("%s: %w", method, res.err)
		}
		if out != nil && len(res.result) > 0 {
			return json.Unmarshal(res.result, out)
		}
		return nil
	}
}

func (c *Client) drop(id int) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// readLoop dispatches messages until the socket closes.
func (c *Client) readLoop() {
	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.closed = true
			for id, ch := range c.pending {
				ch <- response{err: err}
				delete(c.pending, id)
			}
			c.mu.Unlock()
			return
		}
		var raw struct {
			ID     int             `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}
		if raw.Method != "" {
			c.mu.Lock()
			handler := c.events
			c.mu.Unlock()
			if handler != nil {
				handler(raw.Method, raw.Params)
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[raw.ID]
		delete(c.pending, raw.ID)
		c.mu.Unlock()
		if ch == nil {
			continue
		}
		if raw.Error != nil {
			ch <- response{err: errors.New(raw.Error.Message)}
		} else {
			ch <- response{result: raw.Result}
		}
	}
}

// OnEvent installs the handler for events the browser pushes.
func (c *Client) OnEvent(handler func(method string, params json.RawMessage)) {
	c.mu.Lock()
	c.events = handler
	c.mu.Unlock()
}

// PauseRequests asks the browser to hold requests whose URL matches pattern
// (for example "*://*/passport/v1/auth/*") so their address can be read before
// the server sees them.
func (c *Client) PauseRequests(ctx context.Context, pattern string) error {
	return c.call(ctx, "Fetch.enable", map[string]any{
		"patterns": []map[string]any{{
			"urlPattern":   pattern,
			"requestStage": "Request",
		}},
	}, nil)
}

// ContinueRequest lets a paused request through unchanged.
func (c *Client) ContinueRequest(ctx context.Context, requestID string) error {
	return c.call(ctx, "Fetch.continueRequest", map[string]any{"requestId": requestID}, nil)
}

// DropRequest lets a paused request fail instead of reaching the server.
func (c *Client) DropRequest(ctx context.Context, requestID string) error {
	return c.call(ctx, "Fetch.failRequest", map[string]any{
		"requestId":   requestID,
		"errorReason": "Aborted",
	}, nil)
}

// Navigate loads url in the attached page.
func (c *Client) Navigate(ctx context.Context, url string) error {
	return c.call(ctx, "Page.navigate", map[string]any{"url": url}, nil)
}

// Evaluate runs expression in the page and decodes its JSON value into out.
func (c *Client) Evaluate(ctx context.Context, expression string, out any) error {
	var res struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	params := map[string]any{
		"expression":    expression,
		"awaitPromise":  true,
		"returnByValue": true,
	}
	if err := c.call(ctx, "Runtime.evaluate", params, &res); err != nil {
		return err
	}
	if res.ExceptionDetails != nil {
		return fmt.Errorf("页面脚本错误：%s", res.ExceptionDetails.Text)
	}
	if out == nil || len(res.Result.Value) == 0 {
		return nil
	}
	return json.Unmarshal(res.Result.Value, out)
}

// Cookies returns every cookie the browser holds.
func (c *Client) Cookies(ctx context.Context) ([]Cookie, error) {
	var res struct {
		Cookies []Cookie `json:"cookies"`
	}
	if err := c.call(ctx, "Network.getAllCookies", nil, &res); err != nil {
		return nil, err
	}
	return res.Cookies, nil
}

// Enable turns on the domains this package uses.
func (c *Client) Enable(ctx context.Context) error {
	if err := c.call(ctx, "Network.enable", nil, nil); err != nil {
		return err
	}
	return c.call(ctx, "Page.enable", nil, nil)
}

// FreePort returns a loopback port nothing listens on.
func FreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// CookiesFor returns the cookies that belong to host, in the shape the aTrust
// client stores them.
func CookiesFor(cookies []Cookie, host string) []Cookie {
	out := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		domain := strings.TrimPrefix(strings.ToLower(c.Domain), ".")
		if domain == strings.ToLower(host) || strings.HasSuffix(domain, "."+strings.ToLower(host)) {
			out = append(out, c)
		}
	}
	return out
}
