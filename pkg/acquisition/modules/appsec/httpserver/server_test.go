package httpserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/ja4h"
)

// startServer serves h on a loopback listener until the test ends.
func startServer(t *testing.T, h http.Handler) string {
	t.Helper()

	var listenConfig net.ListenConfig

	l, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &Server{
		Handler:           h,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       2 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()

	t.Cleanup(func() {
		// t.Context() is already canceled when cleanups run.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Second)
		defer cancel()

		_ = srv.Shutdown(ctx)

		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
			t.Error("server did not return from Serve in time")
		}
	})

	return l.Addr().String()
}

// dial connects to addr and returns the connection with a reader for responses.
func dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()

	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	return c, bufio.NewReader(c)
}

// connClosed reports whether the server closed c once the response was read.
// A read timeout means the connection is still open.
func connClosed(t *testing.T, c net.Conn) bool {
	t.Helper()

	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	require.Error(t, err, "unexpected bytes after the response")

	return true
}

type seenRequest struct {
	Method, Path, Header, Body string
}

func TestServer(t *testing.T) {
	tests := []struct {
		name       string
		request    string
		wantStatus int
		wantSeen   *seenRequest // nil: the handler must not be called
		wantClosed bool
	}{
		{
			name:       "GET",
			request:    "GET /foo HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodGet, Path: "/foo"},
			wantClosed: true,
		},
		{
			// net/http answers 400 here, which would hide the request from the WAF.
			name:       "control char in header value reaches the handler",
			request:    "GET / HTTP/1.1\r\nHost: x\r\nX-Test: ab\x01cd\r\nConnection: close\r\n\r\n",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodGet, Path: "/", Header: "ab\x01cd"},
			wantClosed: true,
		},
		{
			name:       "POST with content-length",
			request:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello body",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodPost, Path: "/", Body: "hello body"},
			wantClosed: true,
		},
		{
			name:       "POST chunked",
			request:    "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodPost, Path: "/", Body: "hello world"},
			wantClosed: true,
		},
		{
			name:       "HTTP/1.0 closes by default",
			request:    "GET / HTTP/1.0\r\nHost: x\r\n\r\n",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodGet, Path: "/"},
			wantClosed: true,
		},
		{
			name:       "HTTP/1.1 stays open by default",
			request:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			wantStatus: http.StatusOK,
			wantSeen:   &seenRequest{Method: http.MethodGet, Path: "/"},
			wantClosed: false,
		},
		{
			name:       "malformed request line",
			request:    "GARBAGE\r\n\r\n",
			wantStatus: http.StatusBadRequest,
			wantClosed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seen atomic.Pointer[seenRequest]

			addr := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				seen.Store(&seenRequest{
					Method: r.Method,
					Path:   r.URL.Path,
					Header: r.Header.Get("X-Test"),
					Body:   string(body),
				})
				_, _ = w.Write([]byte("ok"))
			}))

			c, br := dial(t, addr)
			_, err := io.WriteString(c, tc.request)
			require.NoError(t, err)

			resp, err := http.ReadResponse(br, nil)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			require.Equal(t, tc.wantStatus, resp.StatusCode)
			require.Equal(t, tc.wantSeen, seen.Load())
			require.Equal(t, tc.wantClosed, connClosed(t, c))
		})
	}
}

func TestServer_KeepAlive(t *testing.T) {
	var count atomic.Int32

	addr := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))

	c, br := dial(t, addr)

	for range 2 {
		_, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		require.NoError(t, err)

		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	require.Equal(t, int32(2), count.Load())
}

func TestServer_Shutdown(t *testing.T) {
	var listenConfig net.ListenConfig

	l, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &Server{Handler: http.NotFoundHandler()}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	require.NoError(t, srv.Shutdown(ctx))

	select {
	case err := <-done:
		// run.go relies on this to tell a clean stop from a failure.
		require.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

// The header order only reaches ja4h through the request context.
func TestServer_HeaderOrderInContext(t *testing.T) {
	var seen atomic.Value

	addr := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(ja4h.HeaderOrder(r.Context()))
		_, _ = w.Write([]byte("ok"))
	}))

	c, br := dial(t, addr)
	_, err := io.WriteString(c, "GET / HTTP/1.1\r\nZeta: 1\r\nHost: x\r\nAlpha: 2\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	_ = resp.Body.Close()

	require.Equal(t, []string{"Zeta", "Host", "Alpha", "Connection"}, seen.Load())
}
