package httpserver

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// startServer launches a Server on a loopback listener and returns the address
// plus a teardown function.
func startServer(t *testing.T, h http.Handler) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{
		Handler:           h,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(l)
	}()
	addr := l.Addr().String()
	return addr, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
			t.Errorf("server did not return from Serve in time")
		}
	}
}

// dial returns a connected client with a bufio.Reader for reading the response.
func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c, bufio.NewReader(c)
}

func TestServer_BasicGET(t *testing.T) {
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/foo" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GET /foo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("body %q", body)
	}
}

// TestServer_AcceptsControlCharsInHeader is the key acceptance test: a header
// value containing a control character (0x01) — which net/http rejects with a
// 400 — must be delivered to the handler unchanged.
func TestServer_AcceptsControlCharsInHeader(t *testing.T) {
	var seen atomic.Value
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("X-Evil"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Evil: ab\x01cd\r\nConnection: close\r\n\r\n")

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	got, _ := seen.Load().(string)
	if got != "ab\x01cd" {
		t.Errorf("handler received %q, want %q", got, "ab\x01cd")
	}
}

func TestServer_KeepAlive(t *testing.T) {
	var count atomic.Int32
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()

	// Send two requests on the same connection.
	for i := 0; i < 2; i++ {
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if got := count.Load(); got != 2 {
		t.Errorf("handler called %d times, want 2", got)
	}
}

func TestServer_ConnectionClose(t *testing.T) {
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bye"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	// http.ReadResponse strips Connection into resp.Close — check there.
	if !resp.Close {
		t.Errorf("resp.Close = false, want true")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	one := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(one); err == nil {
		t.Errorf("expected error reading from closed connection")
	}
}

func TestServer_HTTP10DefaultsClose(t *testing.T) {
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	// HTTP/1.0 without keep-alive: server should close.
	one := make([]byte, 1)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(one); err == nil {
		t.Errorf("expected close after HTTP/1.0 response")
	}
}

func TestServer_PostWithBody(t *testing.T) {
	var got []byte
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = b
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	body := "hello body"
	_, _ = io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\n"+body)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if string(got) != body {
		t.Errorf("handler got body %q, want %q", got, body)
	}
}

func TestServer_PostChunkedBody(t *testing.T) {
	var got []byte
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = b
		_, _ = w.Write([]byte("ok"))
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	chunked := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	_, _ = io.WriteString(c, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"+chunked)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	if string(got) != "hello world" {
		t.Errorf("handler got %q", got)
	}
}

func TestServer_BadRequestLine(t *testing.T) {
	addr, stop := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("handler should not be called for malformed request")
	}))
	defer stop()

	c, br := dial(t, addr)
	defer c.Close()
	_, _ = io.WriteString(c, "GARBAGE\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestServer_Shutdown(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}),
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != http.ErrServerClosed {
			t.Errorf("Serve returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Errorf("Serve did not return after Shutdown")
	}
}
