package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// handleHTTP serves one HTTP-proxy request on the same listener as SOCKS5.
// It supports CONNECT (HTTPS and any TCP) and absolute-URI forwarding.
func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		s.logf("http: %v", err)
		return
	}
	target := req.Host
	if req.Method == http.MethodConnect {
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		remote, err := s.dial(target)
		if err != nil {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			s.logf("http connect %s: %v", target, err)
			return
		}
		defer s.closeRemote(remote)
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		pipe(conn, remote)
		return
	}

	if !req.URL.IsAbs() || req.URL.Host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		s.logf("http: not a proxy request")
		return
	}
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	remote, err := s.dial(host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		s.logf("http get %s: %v", host, err)
		return
	}
	defer s.closeRemote(remote)
	_ = conn.SetDeadline(time.Time{})
	// Rewrite the absolute-URI request to origin form for the server.
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")
	if err := req.Write(remote); err != nil {
		return
	}
	pipe(conn, remote)
}

func (s *Server) dial(target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	remote, err := s.opts.Dial(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	if !s.track(remote) {
		_ = remote.Close()
		return nil, fmt.Errorf("server closed")
	}
	return remote, nil
}

func (s *Server) closeRemote(remote net.Conn) {
	s.untrack(remote)
	_ = remote.Close()
}
