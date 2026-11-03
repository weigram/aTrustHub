// Package proxy serves SOCKS5 on a local address and sends the connections
// it accepts through a Dial function, which the VPN side provides.
//
// Only CONNECT is supported: aTrust carries TCP through its L3 tunnel well,
// and every browser and most tools take a SOCKS5 proxy for TCP. UDP
// ASSOCIATE is answered with "command not supported" rather than failing
// silently.
package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Auth is the username and 口令 a SOCKS5 client must give. A nil
// Auth accepts any client, which is what a loopback listener wants.
type Auth struct {
	Username   string
	Credential string
}

// Options configure a Server.
type Options struct {
	// Addr is the address to listen on, such as "127.0.0.1:1080".
	Addr string
	// Dial opens the connection to the destination the client asked for.
	// It must be safe for concurrent use.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Auth, when set, asks for a username and 口令.
	Auth *Auth
	// OnConnect and OnClose report the life of one client connection.
	OnConnect func()
	OnClose   func()
	// Logf, when set, receives one line per failure and, at debug, per
	// accepted connection.
	Logf func(format string, args ...any)
}

// Server is a running SOCKS5 listener.
type Server struct {
	opts Options

	mu       sync.Mutex
	ln       net.Listener
	closed   bool
	wg       sync.WaitGroup
	handlers sync.WaitGroup
	conns    map[net.Conn]struct{}
	active   atomic.Int64
	total    atomic.Int64
}

// New returns a Server that is not listening yet.
func New(opts Options) *Server {
	return &Server{opts: opts, conns: map[net.Conn]struct{}{}}
}

// SetDial swaps the dialer used for new connections. When the global TUN
// carries a point's traffic, its proxy must let the system route pick the
// tunnel instead of opening a second tunnel on the same session: a session
// only has one, and the two would fight over it.
func (s *Server) SetDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	s.mu.Lock()
	s.opts.Dial = dial
	s.mu.Unlock()
}

// dialFunc returns the dialer in use, safe to call from a handler.
func (s *Server) dialFunc() func(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.Dial
}

// Start binds the address and accepts clients in the background.
func (s *Server) Start() error {
	if s.opts.Dial == nil {
		return errors.New("proxy: no dialer")
	}
	if s.opts.Addr == "" {
		return errors.New("proxy: no address")
	}
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.opts.Addr, err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()

	s.wg.Add(1)
	go s.accept(ln)
	return nil
}

// Addr returns the address actually bound, after Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Active returns the number of clients connected now.
func (s *Server) Active() int64 { return s.active.Load() }

// Total returns the number of clients accepted since Start.
func (s *Server) Total() int64 { return s.total.Load() }

// Close stops the listener and the clients it accepted.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	s.ln = nil
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
	s.wg.Wait()
	// A handler may be waiting for a dial that honors the proxy's timeout;
	// do not make closing a listener wait for it.
	done := make(chan struct{})
	go func() {
		s.handlers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	return nil
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func (s *Server) logf(format string, args ...any) {
	if s.opts.Logf != nil {
		s.opts.Logf(format, args...)
	}
}

func (s *Server) accept(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			s.logf("accept: %v", err)
			continue
		}
		s.total.Add(1)
		s.active.Add(1)
		if s.opts.OnConnect != nil {
			s.opts.OnConnect()
		}
		s.handlers.Add(1)
		go func() {
			defer s.handlers.Done()
			defer s.active.Add(-1)
			if s.opts.OnClose != nil {
				s.opts.OnClose()
			}
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	if !s.track(conn) {
		_ = conn.Close()
		return
	}
	defer func() {
		s.untrack(conn)
		if r := recover(); r != nil {
			s.logf("connection panic: %v", r)
		}
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReaderSize(conn, 4096)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 0x05 {
		// Not SOCKS5: treat it as an HTTP proxy request (CONNECT or a
		// plain absolute-URI request). Many browsers and proxy switchers
		// handle HTTP proxies better, and CONNECT carries the hostname so
		// the tunnel resolves DNS.
		s.handleHTTP(conn, br)
		return
	}
	if err := s.negotiate(conn, br); err != nil {
		s.logf("handshake: %v", err)
		return
	}
	target, err := s.request(conn, br)
	if err != nil {
		s.logf("request: %v", err)
		return
	}
	// The dial itself may take longer than the handshake; the VPN side
	// applies its own timeout through ctx.
	_ = conn.SetDeadline(time.Time{})

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	remote, err := s.dialFunc()(ctx, "tcp", target)
	cancel()
	if err != nil {
		s.reply(conn, replyHostUnreachable)
		s.logf("dial %s: %v", target, err)
		return
	}
	if !s.track(remote) {
		_ = remote.Close()
		return
	}
	defer func() {
		s.untrack(remote)
		_ = remote.Close()
	}()
	if err := s.reply(conn, replySuccess); err != nil {
		return
	}
	pipe(conn, remote)
}

func (s *Server) negotiate(conn net.Conn, br *bufio.Reader) error {
	version, err := br.ReadByte()
	if err != nil {
		return err
	}
	if version != 5 {
		return fmt.Errorf("unsupported SOCKS version %d", version)
	}
	n, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, int(n))
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	want := byte(0x00)
	if s.opts.Auth != nil {
		want = 0x02
	}
	ok := false
	for _, method := range methods {
		if method == want {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{5, 0xFF})
		return errors.New("no acceptable authentication method")
	}
	if _, err := conn.Write([]byte{5, want}); err != nil {
		return err
	}
	if want != 0x02 {
		return nil
	}
	return s.authenticate(conn, br)
}

func (s *Server) authenticate(conn net.Conn, br *bufio.Reader) error {
	version, err := br.ReadByte()
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported auth version %d", version)
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return err
	}
	user := make([]byte, int(ulen))
	if _, err := io.ReadFull(br, user); err != nil {
		return err
	}
	plen, err := br.ReadByte()
	if err != nil {
		return err
	}
	cred := make([]byte, int(plen))
	if _, err := io.ReadFull(br, cred); err != nil {
		return err
	}
	auth := s.opts.Auth
	userOK := subtle.ConstantTimeCompare(user, []byte(auth.Username)) == 1
	credOK := subtle.ConstantTimeCompare(cred, []byte(auth.Credential)) == 1
	if !userOK || !credOK {
		_, _ = conn.Write([]byte{1, 1})
		return errors.New("bad credentials")
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return err
	}
	return nil
}

func (s *Server) request(conn net.Conn, br *bufio.Reader) (string, error) {
	version, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if version != 5 {
		return "", fmt.Errorf("unsupported request version %d", version)
	}
	cmd, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if _, err := br.ReadByte(); err != nil { // reserved
		return "", err
	}
	atyp, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	var host string
	switch atyp {
	case 0x01:
		var ip [4]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, int(n))
		if _, err := io.ReadFull(br, name); err != nil {
			return "", err
		}
		host = string(name)
	case 0x04:
		var ip [16]byte
		if _, err := io.ReadFull(br, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	default:
		s.reply(conn, replyAddressUnsupported)
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return "", err
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))
	if cmd != 0x01 {
		s.reply(conn, replyCommandUnsupported)
		return "", fmt.Errorf("unsupported command %d", cmd)
	}
	if host == "" || port == 0 {
		s.reply(conn, replyAddressUnsupported)
		return "", errors.New("empty destination")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

const (
	replySuccess            = 0x00
	replyHostUnreachable    = 0x04
	replyCommandUnsupported = 0x07
	replyAddressUnsupported = 0x08
)

func (s *Server) reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// pipe copies both ways until both directions finish. A write half-close
// lets the peer see the end of the request or the response without cutting
// the other direction short.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
