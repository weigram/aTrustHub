package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echoServer returns a TCP server that sends "echo:" and then echoes.
func echoServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = c.Write([]byte("echo:"))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func startProxy(t *testing.T, opts Options) *Server {
	t.Helper()
	s := New(opts)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func socksConnect(t *testing.T, proxyAddr, target string, auth *Auth) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	methods := []byte{0}
	if auth != nil {
		methods = []byte{2}
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	want := byte(0)
	if auth != nil {
		want = 2
	}
	if reply[0] != 5 || reply[1] != want {
		t.Fatalf("greeting reply = %v", reply)
	}
	if auth != nil {
		buf := []byte{1, byte(len(auth.Username))}
		buf = append(buf, auth.Username...)
		buf = append(buf, byte(len(auth.Credential)))
		buf = append(buf, auth.Credential...)
		if _, err := conn.Write(buf); err != nil {
			t.Fatal(err)
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			t.Fatal(err)
		}
		if ar[0] != 1 || ar[1] != 0 {
			t.Fatalf("auth reply = %v", ar)
		}
	}

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != 0 {
		t.Fatalf("connect reply code = %d", head[1])
	}
	switch head[3] {
	case 1:
		_, _ = io.CopyN(io.Discard, conn, 6)
	case 4:
		_, _ = io.CopyN(io.Discard, conn, 18)
	default:
		t.Fatalf("address type %d", head[3])
	}
	return conn
}

func TestConnectAndEcho(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()

	var dialed string
	p := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = addr
			return (&net.Dialer{}).DialContext(ctx, network, echoAddr)
		},
	})
	conn := socksConnect(t, p.Addr().String(), "example.test:80", nil)
	defer conn.Close()

	if dialed != "example.test:80" {
		t.Errorf("dialed %q", dialed)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "echo:" {
		t.Errorf("got %q", buf)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("echo = %q", got)
	}
}

func TestAuthentication(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	p := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Auth: &Auth{Username: "user", Credential: "pw-for-test"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echoAddr)
		},
	})
	conn := socksConnect(t, p.Addr().String(), "example.test:80", &Auth{Username: "user", Credential: "pw-for-test"})
	defer conn.Close()

	// Wrong credentials are refused.
	bad, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	_, _ = bad.Write([]byte{5, 1, 2})
	r := make([]byte, 2)
	_, _ = io.ReadFull(bad, r)
	_, _ = bad.Write([]byte{1, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'})
	ar := make([]byte, 2)
	_, _ = io.ReadFull(bad, ar)
	if ar[1] == 0 {
		t.Error("wrong credentials were accepted")
	}
}

func TestUnsupportedCommand(t *testing.T) {
	p := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, io.EOF
		},
	})
	conn, err := net.Dial("tcp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	_, _ = io.ReadFull(conn, r)
	// UDP ASSOCIATE (command 3), IPv4 127.0.0.1:53.
	_, _ = conn.Write([]byte{5, 3, 0, 1, 127, 0, 0, 1, 0, 53})
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatal(err)
	}
	if head[1] != replyCommandUnsupported {
		t.Errorf("reply = %d", head[1])
	}
}

func TestCloseStopsListener(t *testing.T) {
	p := New(Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, io.EOF
		},
	})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	addr := p.Addr().String()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Error("listener still accepts after Close")
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	echoAddr, closeEcho := echoServer(t)
	defer closeEcho()
	proxy := startProxy(t, Options{
		Addr: "127.0.0.1:0",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", echoAddr, 3*time.Second)
		},
	})
	conn, err := net.DialTimeout("tcp", proxy.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 39)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if !strings.Contains(string(buf), "200") {
		t.Fatalf("connect reply = %q", buf)
	}
	// The echo server sends "echo:" right away.
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "echo:" {
		t.Fatalf("echo = %q", got)
	}
}
