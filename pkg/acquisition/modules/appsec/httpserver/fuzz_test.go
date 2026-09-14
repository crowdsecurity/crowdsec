package httpserver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This server sits in front of the WAF engine, so two classes of bug matter:
// a panic (it takes down the acquisition goroutine) and a parsing divergence
// that hides part of a request from the engine while the protected application
// still sees it. The differential targets below pin our parser to net/http,
// which is both what this server replaces and what bouncers were written
// against: anything net/http accepts, we must read identically.

const (
	fuzzMaxBody     = 1 << 20
	fuzzMaxResponse = 1 << 20
)

// fuzzLimits are deliberately generous so the differential targets compare
// parsing behavior rather than our configurable size limits.
var fuzzLimits = Limits{
	MaxLineSize:    64 * 1024,
	MaxHeaderBytes: 1 << 20,
	MaxHeaderCount: 4096,
}

var errResponseTooLarge = errors.New("response too large")

// replayConn feeds a fixed byte slice to the server and captures what it writes
// back. Reads hit io.EOF at the end of the input so the connection loop always
// terminates, and deadlines are no-ops. Writes past fuzzMaxResponse fail, so a
// response amplification bug surfaces as an error instead of eating memory.
type replayConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newReplayConn(input []byte) *replayConn {
	return &replayConn{in: bytes.NewReader(input)}
}

func (c *replayConn) Read(p []byte) (int, error) { return c.in.Read(p) }

func (c *replayConn) Write(p []byte) (int, error) {
	if c.out.Len()+len(p) > fuzzMaxResponse {
		return 0, errResponseTooLarge
	}

	return c.out.Write(p)
}

func (*replayConn) Close() error                     { return nil }
func (*replayConn) LocalAddr() net.Addr              { return fuzzAddr{} }
func (*replayConn) RemoteAddr() net.Addr             { return fuzzAddr{} }
func (*replayConn) SetDeadline(time.Time) error      { return nil }
func (*replayConn) SetReadDeadline(time.Time) error  { return nil }
func (*replayConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr struct{}

func (fuzzAddr) Network() string { return "fuzz" }
func (fuzzAddr) String() string  { return "127.0.0.1:1" }

var fuzzRequestSeeds = []string{
	"",
	"GET / HTTP/1.1\r\nHost: fuzz\r\n\r\n",
	"GET / HTTP/1.1\nHost: fuzz\nX-Control: a\x01b\n\n",
	"GET / HTTP/1.0\r\n\r\n",
	"GARBAGE\r\n\r\n",
	"\x00\x01\x02\xff\r\n\r\n",
	"GET http://example.com/x?a=1 HTTP/1.1\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nContent-Length: 4\r\n\r\nbody",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nContent-Length: 10\r\n\r\nshort",
	// Request smuggling primitives: the WAF and the origin must agree on where
	// the body starts and ends.
	"POST / HTTP/1.1\r\nHost: fuzz\r\nContent-Length: 4\r\nContent-Length: 40\r\n\r\nbodyGET /smuggled HTTP/1.1\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\nbody\r\n0\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: fuzz\r\nTransfer-Encoding:\tchunked\r\n\r\n4;ext=1\r\nbody\r\n0\r\nTrailer: x\r\n\r\n",
	// Obsolete line folding: net/http joins the continuation, we must not lose it.
	"GET / HTTP/1.1\r\nHost: fuzz\r\nX-Fold: a\r\n b\r\n\r\n",
	"GET /one HTTP/1.1\r\nHost: fuzz\r\n\r\nGET /two HTTP/1.1\r\nHost: fuzz\r\nConnection: close\r\n\r\n",
}

// FuzzServeConn drives a whole connection: pipelined requests, body draining,
// chunked trailers and the response write path.
func FuzzServeConn(f *testing.F) {
	for _, seed := range fuzzRequestSeeds {
		f.Add([]byte(seed))
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler chain dereferences these unconditionally.
		if r.URL == nil || r.Body == nil || r.Header == nil {
			panic("accepted request is missing URL, body or headers")
		}

		if r.Method == "" || r.RequestURI == "" {
			panic("accepted request has an empty request line component")
		}

		if len(r.Header) > fuzzLimits.MaxHeaderCount {
			panic("header count limit not enforced")
		}

		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, fuzzMaxBody))
		w.WriteHeader(http.StatusNoContent)
	})

	f.Fuzz(func(t *testing.T, input []byte) {
		conn := newReplayConn(input)
		srv := &Server{Handler: handler, Limits: fuzzLimits}

		srv.serveConn(conn, false)

		// Anything we put on the wire must frame as HTTP/1.x responses: a
		// bouncer that resynchronises on our reply differently than we intend
		// is a bypass.
		br := bufio.NewReader(bytes.NewReader(conn.out.Bytes()))

		for {
			if _, err := br.Peek(1); err != nil {
				break
			}

			resp, err := http.ReadResponse(br, nil)
			require.NoError(t, err, "unparsable response: %q", conn.out.String())

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)
			resp.Body.Close()
		}
	})
}

// FuzzRequestParity pins the parser to net/http: for every request net/http
// accepts, the WAF must see the same method, target, headers and body.
func FuzzRequestParity(f *testing.F) {
	for _, seed := range fuzzRequestSeeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		stdReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(input)))
		if err != nil {
			// net/http rejects it; this server is deliberately more lenient.
			return
		}

		stdBody, stdBodyErr := io.ReadAll(io.LimitReader(stdReq.Body, fuzzMaxBody))

		br := bufio.NewReaderSize(bytes.NewReader(input), fuzzLimits.MaxLineSize+512)

		req, _, _, err := readRequest(br, newReplayConn(nil), false, fuzzLimits)
		if errors.Is(err, ErrLineTooLong) || errors.Is(err, ErrHeadersTooLarge) || errors.Is(err, ErrTooManyHeaders) {
			t.Skip() // a configured limit, not a parsing divergence
		}

		require.NoError(t, err, "net/http accepted this request, we rejected it")
		require.Equal(t, stdReq.Method, req.Method)
		require.Equal(t, stdReq.RequestURI, req.RequestURI)

		for name, want := range stdReq.Header {
			switch name {
			case "Host", "Content-Length", "Transfer-Encoding":
				// net/http hoists these out of the header map.
				continue
			}

			require.Equal(t, want, req.Header[name], "header %q is not visible to the WAF as net/http sees it", name)
		}

		body, bodyErr := io.ReadAll(io.LimitReader(req.Body, fuzzMaxBody))
		if stdBodyErr != nil {
			return
		}

		require.NoError(t, bodyErr, "net/http read the body, we failed")
		require.Equal(t, string(stdBody), string(body), "the body the WAF inspects differs from the one net/http decodes")
	})
}

// FuzzChunkedParity pins chunk decoding to net/http's. Reading fewer bytes than
// the origin does is a smuggling vector.
func FuzzChunkedParity(f *testing.F) {
	for _, seed := range []string{
		"",
		"0\r\n\r\n",
		"4\r\nbody\r\n0\r\n\r\n",
		"4;ext=1\r\nbody\r\n0\r\n\r\n",
		"+4\r\nbody\r\n0\r\n\r\n",
		"-0\r\n\r\n",
		" 4\r\nbody\r\n0\r\n\r\n",
		"4 \r\nbody\r\n0\r\n\r\n",
		"0x4\r\nbody\r\n0\r\n\r\n",
		"ffffffffffffffff\r\n",
		"4\r\nbody\n0\r\n\r\n",
		"4\nbody\r\n0\r\n\r\n",
		"0;" + strings.Repeat("0", maxChunkSizeLine-4) + "\r\n\r\n",
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		want, stdErr := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(bytes.NewReader(input)), fuzzMaxBody))

		got, err := io.ReadAll(io.LimitReader(newChunkedReader(bufio.NewReaderSize(bytes.NewReader(input), 2*maxChunkSizeLine)), fuzzMaxBody))
		if stdErr != nil {
			return
		}

		require.NoError(t, err, "net/http decoded this chunked body, we failed")
		require.Equal(t, string(want), string(got), "chunk decoding diverges from net/http")
	})
}

// FuzzResponseWriter checks that handler-controlled output cannot split the
// response into something a client would frame as more than one message.
func FuzzResponseWriter(f *testing.F) {
	for _, seed := range []struct {
		name   string
		value  string
		status int
		body   string
	}{
		{"X-Test", "value", http.StatusOK, "body"},
		{"X-Test", "a\r\nInjected: 1", http.StatusOK, ""},
		{"X-Test\r\nInjected", "1", http.StatusOK, ""},
		{"X-Test", "a\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", http.StatusOK, ""},
		{"Content-Length", "999", http.StatusOK, "x"},
		{"", "v", http.StatusOK, ""},
		{"X-Test", "v", 0, ""},
		{"X-Test", "v", -1, ""},
		{"X-Test", "v", 999999, ""},
		{"X-Test", "v", http.StatusSwitchingProtocols, "body"},
		{"X-Test", "v", http.StatusNoContent, "body"},
		{"X-Test", "v", http.StatusNotModified, "body"},
	} {
		f.Add(seed.name, seed.value, seed.status, []byte(seed.body))
	}

	f.Fuzz(func(t *testing.T, name, value string, status int, body []byte) {
		conn := newReplayConn(nil)
		w := newResponseWriter(conn, bufio.NewWriter(conn), "HTTP/1.1")
		w.Header()[name] = []string{value}
		w.WriteHeader(status)
		_, _ = w.Write(body)
		require.NoError(t, w.flush())

		br := bufio.NewReader(bytes.NewReader(conn.out.Bytes()))

		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err, "unparsable response: %q", conn.out.String())

		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()

		want := string(body)
		if !bodyAllowedForStatus(resp.StatusCode) {
			want = ""
		}

		require.Equal(t, want, string(got))

		_, err = br.Peek(1)
		require.ErrorIs(t, err, io.EOF, "trailing bytes after the response: %q", conn.out.String())
	})
}
