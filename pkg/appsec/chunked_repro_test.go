package appsec

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChunkedBodyForwardingMismatch verifies how readRequestBody behaves when a
// request claims Transfer-Encoding: chunked but the on-wire body is empty,
// unframed, or arrives on a connection that is never closed by the client.
//
// This reproduces the regression introduced by PR #4355 (commit 3d5c4d9b1,
// "WAF: enforce body size limitation"), which switched body reading from a
// no-op for chunked requests (io.ReadFull on a 0-length buffer when
// ContentLength==-1) to io.ReadAll, which actually drives Go's internal
// chunkedReader.
//
// The test uses raw TCP — http.Client and httptest.NewRequest both re-encode
// chunked correctly, which would not reproduce the wire-format mismatch
// observed when the nginx Lua bouncer forwards the chunked header without
// putting matching chunk frames on the wire to appsec.
func TestChunkedBodyForwardingMismatch(t *testing.T) {
	// Short read deadline so the test stays fast. Real appsec uses 1s
	// (DefaultBodyReadTimeout in pkg/acquisition/modules/appsec/config.go).
	const readDeadline = 100 * time.Millisecond
	const fastBudget = 50 * time.Millisecond

	logger := log.NewEntry(log.New())

	// The handler returns the body bytes as a hex string in X-Body-Hex so the
	// test can assert on the exact content readRequestBody saw. This is the
	// data appsec would expose to body-related rules.
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// Mirror the real appsec handler at config.go:354.
		if err := http.NewResponseController(rw).SetReadDeadline(time.Now().Add(readDeadline)); err != nil {
			t.Logf("set deadline err: %v", err)
		}

		start := time.Now()
		body, truncated, exceeded, err := readRequestBody(r, BodySettings{}, logger)
		elapsed := time.Since(start)

		rw.Header().Set("X-Body-Len", strconv.Itoa(len(body)))
		rw.Header().Set("X-Body-Hex", hex.EncodeToString(body))
		rw.Header().Set("X-Truncated", strconv.FormatBool(truncated))
		rw.Header().Set("X-Exceeded", strconv.FormatBool(exceeded))
		rw.Header().Set("X-Elapsed-Ms", strconv.FormatInt(elapsed.Milliseconds(), 10))
		if err != nil {
			rw.Header().Set("X-Body-Err", err.Error())
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: time.Second,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		wg.Wait()
	})

	addr := listener.Addr().String()

	type expectation struct {
		// minStatus..maxStatus describes the acceptable status code range.
		// Exact-match cases set both to the same value.
		minStatus, maxStatus int
		// allowDeadline=true means the response is expected to take ~readDeadline.
		// allowDeadline=false means it should come back well before the deadline.
		allowDeadline bool
		// expectBody, if non-nil, is the exact decoded body readRequestBody
		// must produce. Set on positive scenarios (well-framed chunked bodies)
		// to confirm body-related rules would see the right bytes.
		expectBody *string
	}

	bodyOf := func(s string) *string { return &s }

	// helper: render N bytes as hex chunks separated by chunked framing.
	chunked := func(parts ...string) string {
		var sb strings.Builder
		for _, p := range parts {
			fmt.Fprintf(&sb, "%x\r\n%s\r\n", len(p), p)
		}
		sb.WriteString("0\r\n\r\n")
		return sb.String()
	}

	cases := []struct {
		name      string
		writeBody string
		halfClose bool // close our write half after sending
		expect    expectation
	}{
		{
			// Control: properly framed empty chunked body — the happy path.
			name:      "A_well_formed_chunked_empty",
			writeBody: "0\r\n\r\n",
			halfClose: true,
			expect:    expectation{minStatus: 200, maxStatus: 200, allowDeadline: false},
		},
		{
			// chunked header, zero bytes, then close. chunkedReader gets EOF
			// reading the chunk-size line; readRequestBody swallows
			// io.ErrUnexpectedEOF (request.go:333-335).
			name:      "B_chunked_header_no_body_close",
			writeBody: "",
			halfClose: true,
			expect:    expectation{minStatus: 200, maxStatus: 200, allowDeadline: false},
		},
		{
			// chunked header, zero bytes, connection STAYS OPEN. chunkedReader
			// blocks; the read deadline fires; readRequestBody swallows the
			// net.Error timeout. THIS IS THE FAILURE MODE that matches the
			// bouncer logs from CVE-2023-34362 hubtest.
			name:      "C_chunked_header_no_body_keepopen",
			writeBody: "",
			halfClose: false,
			expect:    expectation{minStatus: 200, maxStatus: 200, allowDeadline: true},
		},
		{
			// Plain unframed bytes with a chunked header. Depending on whether
			// the parser hits a CRLF before EOF, this either errors as
			// "malformed chunked encoding" (-> 500) or as ErrUnexpectedEOF
			// (swallowed -> 200). Either way it should return promptly.
			name:      "D_chunked_header_plain_body",
			writeBody: "body content",
			halfClose: true,
			expect:    expectation{minStatus: 200, maxStatus: 599, allowDeadline: false},
		},
		{
			// Same wire shape as the failing hubtest (terminator only) but
			// without closing — confirms a properly framed empty chunked body
			// returns fast even on a kept-open connection.
			name:      "E_well_formed_chunked_empty_keepopen",
			writeBody: "0\r\n\r\n",
			halfClose: false,
			expect:    expectation{minStatus: 200, maxStatus: 200, allowDeadline: false},
		},
		{
			// Garbage chunk-size header followed by CRLF — should reliably
			// trigger "malformed chunked encoding" and 500.
			name:      "F_chunked_header_invalid_size",
			writeBody: "ZZ\r\n",
			halfClose: true,
			expect:    expectation{minStatus: 500, maxStatus: 500, allowDeadline: false},
		},
		{
			// Positive: a single-chunk body with real content. readRequestBody
			// must hand the decoded bytes ("hello world") back so rules can
			// inspect them.
			name:      "G_single_chunk_with_content",
			writeBody: chunked("hello world"),
			halfClose: true,
			expect: expectation{
				minStatus: 200, maxStatus: 200, allowDeadline: false,
				expectBody: bodyOf("hello world"),
			},
		},
		{
			// Positive, kept-open: same as G but without half-close. The
			// terminator must be enough for chunkedReader to stop without
			// hitting the read deadline.
			name:      "H_single_chunk_keepopen",
			writeBody: chunked("hello world"),
			halfClose: false,
			expect: expectation{
				minStatus: 200, maxStatus: 200, allowDeadline: false,
				expectBody: bodyOf("hello world"),
			},
		},
		{
			// Positive: multiple chunks must be reassembled in order.
			name:      "I_multi_chunk",
			writeBody: chunked("foo=", "bar&", "baz=qux"),
			halfClose: true,
			expect: expectation{
				minStatus: 200, maxStatus: 200, allowDeadline: false,
				expectBody: bodyOf("foo=bar&baz=qux"),
			},
		},
		{
			// Positive: a SQLi-shaped payload sent in two chunks — the kind of
			// thing a body-rule would match. Confirms the bytes appsec sees
			// after dechunking are byte-identical to the logical body.
			name: "J_multi_chunk_sqli_payload",
			writeBody: chunked(
				"username=admin&password=' OR ",
				"1=1 -- ",
			),
			halfClose: true,
			expect: expectation{
				minStatus: 200, maxStatus: 200, allowDeadline: false,
				expectBody: bodyOf("username=admin&password=' OR 1=1 -- "),
			},
		},
		{
			// Positive: a moderately large body (8 KiB), single chunk. Stays
			// well under DefaultMaxBodySize (10 MiB) so no truncation.
			name:      "K_large_single_chunk",
			writeBody: chunked(strings.Repeat("A", 8*1024)),
			halfClose: true,
			expect: expectation{
				minStatus: 200, maxStatus: 200, allowDeadline: false,
				expectBody: bodyOf(strings.Repeat("A", 8*1024)),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			require.NoError(t, err)
			defer conn.Close()

			req := "POST / HTTP/1.1\r\n" +
				"Host: x\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"\r\n" +
				tc.writeBody

			start := time.Now()
			_, err = conn.Write([]byte(req))
			require.NoError(t, err)

			if tc.halfClose {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.CloseWrite()
				}
			}

			// Bound how long we wait for a response so a hung server doesn't hang the test.
			_ = conn.SetReadDeadline(time.Now().Add(readDeadline + 2*time.Second))

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.NoError(t, err, "should get an HTTP response within the timeout")
			elapsed := time.Since(start)
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)

			t.Logf("scenario %s: status=%d elapsed=%s X-Body-Len=%s X-Body-Err=%q X-Elapsed-Ms=%s",
				tc.name,
				resp.StatusCode, elapsed,
				resp.Header.Get("X-Body-Len"),
				resp.Header.Get("X-Body-Err"),
				resp.Header.Get("X-Elapsed-Ms"),
			)

			assert.GreaterOrEqual(t, resp.StatusCode, tc.expect.minStatus)
			assert.LessOrEqual(t, resp.StatusCode, tc.expect.maxStatus)

			if tc.expect.allowDeadline {
				assert.GreaterOrEqual(t, elapsed, readDeadline-10*time.Millisecond,
					"expected handler to wait at least one read deadline (~%s)", readDeadline)
			} else {
				assert.Less(t, elapsed, readDeadline+fastBudget,
					"expected handler to return faster than the read deadline; got %s", elapsed)
			}

			if tc.expect.expectBody != nil {
				gotHex := resp.Header.Get("X-Body-Hex")
				gotBody, err := hex.DecodeString(gotHex)
				require.NoError(t, err, "X-Body-Hex must decode")
				assert.Equal(t, *tc.expect.expectBody, string(gotBody),
					"readRequestBody must return the dechunked body so body rules can inspect it")
			}
		})
	}
}
