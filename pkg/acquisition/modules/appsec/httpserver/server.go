// This server is NOT a general-purpose HTTP server. It speaks only HTTP/1.x,
// trusts its peers (deployments are expected to put it behind a bouncer), and
// makes minimal effort to defend against pathological clients beyond enforcing
// configurable size limits.
// Its goal is to be able to accept almost any request that looks like HTTP, even if it's technically malformed
package httpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// Server is a minimal lenient HTTP/1.x server. The zero value is usable; set
// Handler before calling Serve / ServeTLS.
type Server struct {
	Handler http.Handler

	// TLSConfig is used by ServeTLS. If nil, a fresh tls.Config is created.
	TLSConfig *tls.Config

	// ReadHeaderTimeout bounds the time spent reading the request line and headers.
	// Zero disables the timeout (matching net/http's default).
	ReadHeaderTimeout time.Duration

	// IdleTimeout bounds the wait for the next request on a keep-alive connection.
	// Zero disables the timeout.
	IdleTimeout time.Duration

	// WriteTimeout bounds the time spent writing the response. Zero disables it.
	WriteTimeout time.Duration

	// Limits bounds request line / header sizes. Zero values fall back to defaults.
	Limits Limits

	// Logger receives diagnostic messages. May be nil.
	Logger *log.Entry

	mu          sync.Mutex
	listeners   map[net.Listener]struct{}
	activeConns map[net.Conn]struct{}
	inShutdown  atomic.Bool
}

// Serve accepts connections on l and serves each one in its own goroutine.
// Returns http.ErrServerClosed after a successful Shutdown.
func (s *Server) Serve(l net.Listener) error {
	return s.serve(l, false)
}

// ServeTLS wraps l in a TLS listener using TLSConfig and the provided certificate
// pair, then serves on it.
func (s *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	cfg := s.TLSConfig
	if cfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}
	return s.serve(tls.NewListener(l, cfg), true)
}

func (s *Server) serve(l net.Listener, isTLS bool) error {
	if s.inShutdown.Load() {
		return http.ErrServerClosed
	}
	s.trackListener(l, true)
	defer s.trackListener(l, false)

	var tempDelay time.Duration
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.inShutdown.Load() {
				return http.ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				s.logf("accept temporary error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		go s.serveConn(conn, isTLS)
	}
}

func (s *Server) serveConn(conn net.Conn, isTLS bool) {
	s.trackConn(conn, true)
	defer s.trackConn(conn, false)
	defer conn.Close()

	limits := s.Limits.withDefaults()
	// Size the read buffer to fit the longest acceptable line so readLine can
	// use bufio.ReadSlice (zero-alloc) without hitting ErrBufferFull.
	br := bufio.NewReaderSize(conn, limits.MaxLineSize+512)
	bw := bufio.NewWriter(conn)
	first := true

	for {
		if s.inShutdown.Load() {
			return
		}

		// Bound the wait for the next request byte: ReadHeaderTimeout on the
		// first request, IdleTimeout (falling back to ReadHeaderTimeout) for
		// subsequent ones on the same keep-alive connection.
		wait := s.ReadHeaderTimeout
		if !first && s.IdleTimeout > 0 {
			wait = s.IdleTimeout
		}
		if wait > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(wait))
		}
		if _, err := br.Peek(1); err != nil {
			return
		}
		first = false

		// Now bound the time to actually parse the headers.
		if s.ReadHeaderTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.ReadHeaderTimeout))
		}

		req, info, closeAfter, err := s.readRequest(br, conn, isTLS, limits)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logf("read request: %v", err)
				writeBadRequest(bw)
			}
			return
		}

		// Clear the deadline; the handler may set its own via http.NewResponseController.
		_ = conn.SetReadDeadline(time.Time{})
		if s.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		rw := newResponseWriter(conn, bw, req.Proto)
		rw.closeConn = closeAfter

		s.Handler.ServeHTTP(rw, req)

		// Drain any unread body so the next request lands on a clean boundary.
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}

		// For chunked requests we still need to consume the trailer section
		// (optional trailer headers + final CRLF) that http.NewChunkedReader
		// leaves on the wire.
		if info.Chunked {
			if err := drainChunkedTrailer(br, limits); err != nil {
				s.logf("drain chunked trailer: %v", err)
				_ = rw.flush()
				return
			}
		}

		if err := rw.flush(); err != nil {
			s.logf("write response: %v", err)
			return
		}

		if closeAfter {
			return
		}
	}
}

func (s *Server) readRequest(br *bufio.Reader, conn net.Conn, isTLS bool, limits Limits) (*http.Request, bodyInfo, bool, error) {
	rl, err := readRequestLine(br, limits.MaxLineSize)
	if err != nil {
		return nil, bodyInfo{}, true, err
	}
	headers, err := readHeaders(br, limits)
	if err != nil {
		return nil, bodyInfo{}, true, err
	}
	info, err := newBodyReader(br, headers)
	if err != nil {
		return nil, bodyInfo{}, true, err
	}

	req := &http.Request{
		Method:           rl.Method,
		Proto:            rl.Proto,
		ProtoMajor:       rl.ProtoMajor,
		ProtoMinor:       rl.ProtoMinor,
		Header:           headers,
		Body:             info.Body,
		ContentLength:    info.ContentLength,
		TransferEncoding: info.TransferEncoding,
		Host:             headers.Get("Host"),
		RequestURI:       rl.Target,
		RemoteAddr:       conn.RemoteAddr().String(),
	}
	if u, err := url.ParseRequestURI(rl.Target); err == nil {
		req.URL = u
	} else if u, err := url.Parse(rl.Target); err == nil {
		req.URL = u
	} else {
		req.URL = &url.URL{Path: rl.Target}
	}

	if isTLS {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			req.TLS = &state
		}
	}

	// (*http.Request).Context() returns context.Background() when the unexported
	// ctx field is nil, so we skip WithContext entirely — it would clone the
	// whole request struct for no benefit.

	return req, info, shouldClose(rl.ProtoMajor, rl.ProtoMinor, headers), nil
}

func shouldClose(major, minor int, h http.Header) bool {
	connHdr := strings.ToLower(h.Get("Connection"))
	if major < 1 || (major == 1 && minor < 1) {
		return !strings.Contains(connHdr, "keep-alive")
	}
	return strings.Contains(connHdr, "close")
}

func writeBadRequest(bw *bufio.Writer) {
	_, _ = bw.WriteString("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	_ = bw.Flush()
}

func drainChunkedTrailer(br *bufio.Reader, limits Limits) error {
	for {
		line, err := readLine(br, limits.MaxLineSize)
		if err != nil {
			return err
		}
		if len(line) == 0 {
			return nil
		}
	}
}

// Shutdown stops accepting new connections and waits for active connections to
// finish, up to ctx's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	s.inShutdown.Store(true)
	s.mu.Lock()
	for l := range s.listeners {
		_ = l.Close()
	}
	s.mu.Unlock()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		n := len(s.activeConns)
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close immediately closes all listeners and active connections without waiting.
func (s *Server) Close() error {
	s.inShutdown.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	for l := range s.listeners {
		_ = l.Close()
	}
	for c := range s.activeConns {
		_ = c.Close()
	}
	return nil
}

func (s *Server) trackListener(l net.Listener, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[net.Listener]struct{})
	}
	if add {
		s.listeners[l] = struct{}{}
	} else {
		delete(s.listeners, l)
	}
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeConns == nil {
		s.activeConns = make(map[net.Conn]struct{})
	}
	if add {
		s.activeConns[c] = struct{}{}
	} else {
		delete(s.activeConns, c)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Debugf(format, args...)
	}
}
