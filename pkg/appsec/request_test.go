package appsec

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"runtime"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestBodyDumper(t *testing.T) {
	tests := []struct {
		name   string
		req    *ParsedRequest
		expect *ParsedRequest
		filter func(r *ReqDumpFilter) *ReqDumpFilter
	}{
		{
			name: "default filter (cookie+authorization stripped + no body)",
			req: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"foo": {"bar", "baz"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r
			},
		},
		{
			name: "explicit empty filter",
			req: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			expect: &ParsedRequest{
				Body:    []byte("yo some body"),
				Headers: map[string][]string{"cookie": {"toto"}, "authorization": {"tata"}, "foo": {"bar", "baz"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.NoFilters()
			},
		},
		{
			name: "filter header",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}, "test2": {"tata"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithNoBody().WithHeadersNameFilter("test2")
			},
		},
		{
			name: "filter header content",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}, "test2": {"tata"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"test1": {"toto"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithHeadersContentFilter("tata")
			},
		},
		{
			name: "with headers",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"cookie1": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"cookie1": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithHeaders()
			},
		},
		{
			name: "drop headers",
			req: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte{},
				Headers: map[string][]string{},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithNoHeaders()
			},
		},
		{
			name: "with body",
			req: &ParsedRequest{
				Body:    []byte("toto"),
				Headers: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Body:    []byte("toto"),
				Headers: map[string][]string{"toto": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithBody()
			},
		},
		{
			name: "with empty args filter",
			req: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithEmptyArgsFilters()
			},
		},
		{
			name: "with args name filter",
			req: &ParsedRequest{
				Args: map[string][]string{"toto": {"lol"}, "totolol": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"totolol": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithArgsNameFilter("toto")
			},
		},
		{
			name: "WithEmptyHeadersFilters",
			req: &ParsedRequest{
				Args: map[string][]string{"cookie": {"lol"}, "totolol": {"lol"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"cookie": {"lol"}, "totolol": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithEmptyHeadersFilters()
			},
		},
		{
			name: "WithArgsContentFilters",
			req: &ParsedRequest{
				Args: map[string][]string{"test": {"lol"}, "test2": {"toto"}},
			},
			expect: &ParsedRequest{
				Args: map[string][]string{"test": {"lol"}},
			},
			filter: func(r *ReqDumpFilter) *ReqDumpFilter {
				return r.WithArgsContentFilter("toto")
			},
		},
	}

	for idx, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orig_dr := test.req.DumpRequest()
			result := test.filter(orig_dr).GetFilteredRequest()

			if len(result.Body) != len(test.expect.Body) {
				t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(test.req.Body), len(test.expect.Body))
			}
			if len(result.Headers) != len(test.expect.Headers) {
				t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(test.req.Headers), len(test.expect.Headers))
			}
			for k, v := range result.Headers {
				if len(v) != len(test.expect.Headers[k]) {
					t.Fatalf("test %d (%s) failed, got %d, expected %d", idx, test.name, len(v), len(test.expect.Headers[k]))
				}
			}
		})
	}
}

func makeTestRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()

	var bodyReader io.ReadCloser
	if body != nil {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	}

	r := &http.Request{
		RemoteAddr: "1.2.3.4:1234",
		Body:       bodyReader,
		Header: http.Header{
			IPHeaderName:   []string{"1.2.3.4"},
			URIHeaderName:  []string{"/test"},
			VerbHeaderName: []string{"POST"},
		},
	}

	return r
}

func TestNewParsedRequestFromRequestBodyLimit(t *testing.T) {
	logger := log.WithField("test", "body-limit")

	tests := []struct {
		name             string
		body             []byte
		settings         BodySettings
		expectBody       []byte // nil means expect empty/nil body
		expectTruncated  bool
		expectExceeded   bool
	}{
		{
			name:     "no body",
			body:     nil,
			settings: BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
		},
		{
			name:       "within limit",
			body:       bytes.Repeat([]byte("x"), 5),
			settings:   BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectBody: bytes.Repeat([]byte("x"), 5),
		},
		{
			name:       "exactly at limit",
			body:       bytes.Repeat([]byte("x"), 10),
			settings:   BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectBody: bytes.Repeat([]byte("x"), 10),
		},
		{
			name:           "over limit – drop",
			body:           bytes.Repeat([]byte("x"), 15),
			settings:       BodySettings{MaxSize: 10, Action: BodySizeActionDrop},
			expectExceeded: true,
		},
		{
			name:            "over limit – partial",
			body:            bytes.Repeat([]byte("x"), 15),
			settings:        BodySettings{MaxSize: 10, Action: BodySizeActionPartial},
			expectBody:      bytes.Repeat([]byte("x"), 10),
			expectTruncated: true,
		},
		{
			name:     "over limit – allow",
			body:     bytes.Repeat([]byte("x"), 15),
			settings: BodySettings{MaxSize: 10, Action: BodySizeActionAllow},
		},
		{
			name:       "zero MaxSize uses default (small body fits)",
			body:       bytes.Repeat([]byte("x"), 5),
			settings:   BodySettings{},
			expectBody: bytes.Repeat([]byte("x"), 5),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := makeTestRequest(t, test.body)

			parsed, err := NewParsedRequestFromRequest(r, logger, test.settings)
			require.NoError(t, err)

			require.Equal(t, test.expectTruncated, parsed.BodyTruncated)
			require.Equal(t, test.expectExceeded, parsed.BodySizeExceeded)
			require.Equal(t, test.expectBody, parsed.Body)
		})
	}
}

func compressGzip(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func compressZlib(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func compressFlate(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.Bytes()
}

func TestNewParsedRequestFromRequestDecompress(t *testing.T) {
	logger := log.WithField("test", "body-decompress")

	payload := []byte("payload=MALICIOUS")
	gzPayload := compressGzip(t, payload)
	long := bytes.Repeat([]byte("0123456789abcdef"), 4096)
	attack := []byte("&payload=MALICIOUS")
	rawDeflate := compressFlate(t, payload)
	gzTrailing := append(compressGzip(t, []byte("a=1")), attack...)
	zlibTrailing := append(compressZlib(t, []byte("a=1")), attack...)
	gzMultiMember := append(compressGzip(t, []byte("a=1")), compressGzip(t, attack)...)
	gzOfPlain := compressGzip(t, payload)

	var named bytes.Buffer
	nw := gzip.NewWriter(&named)
	nw.Name = string(attack)
	_, err := nw.Write([]byte("a=1"))
	require.NoError(t, err)
	require.NoError(t, nw.Close())
	gzNamed := named.Bytes()

	gzBadCRC := compressGzip(t, payload)
	gzBadCRC[len(gzBadCRC)-8] ^= 0xff

	// ~1KB compressed, 1MB decompressed.
	bomb := compressGzip(t, make([]byte, 1<<20))
	nestedBomb := compressGzip(t, compressGzip(t, make([]byte, 1<<20)))

	tests := []struct {
		name            string
		body            []byte
		encoding        []string
		settings        BodySettings
		expectBody      []byte
		expectPrefixOf  []byte // set instead of expectBody when only a non-empty prefix is predictable
		expectTruncated bool
		expectExceeded  bool
	}{
		{
			name:       "disabled – body left compressed",
			body:       gzPayload,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024},
			expectBody: gzPayload,
		},
		{
			name:       "gzip",
			body:       gzPayload,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "x-gzip, case insensitive",
			body:       gzPayload,
			encoding:   []string{"X-GZip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "deflate (zlib)",
			body:       compressZlib(t, payload),
			encoding:   []string{"deflate"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "stacked encodings are undone in reverse order",
			body:       compressGzip(t, compressZlib(t, payload)),
			encoding:   []string{"deflate, gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "stacked encodings over several headers",
			body:       compressGzip(t, compressZlib(t, payload)),
			encoding:   []string{"deflate", "identity", "gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "decompressed exactly at limit",
			body:       compressGzip(t, bytes.Repeat([]byte("x"), 100)),
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 100, Decompress: true},
			expectBody: bytes.Repeat([]byte("x"), 100),
		},
		{
			name:           "bomb – drop",
			body:           bomb,
			encoding:       []string{"gzip"},
			settings:       BodySettings{MaxSize: 4096, Action: BodySizeActionDrop, Decompress: true},
			expectExceeded: true,
		},
		{
			name:     "bomb – allow",
			body:     bomb,
			encoding: []string{"gzip"},
			settings: BodySettings{MaxSize: 4096, Action: BodySizeActionAllow, Decompress: true},
		},
		{
			name:            "bomb – partial",
			body:            bomb,
			encoding:        []string{"gzip"},
			settings:        BodySettings{MaxSize: 4096, Action: BodySizeActionPartial, Decompress: true},
			expectBody:      make([]byte, 4096),
			expectTruncated: true,
		},
		{
			name:           "nested bomb – drop",
			body:           nestedBomb,
			encoding:       []string{"gzip, gzip"},
			settings:       BodySettings{MaxSize: 4096, Action: BodySizeActionDrop, Decompress: true},
			expectExceeded: true,
		},
		{
			name:            "compressed body over limit – partial decodes the kept prefix",
			body:            compressZlib(t, long),
			encoding:        []string{"deflate"},
			settings:        BodySettings{MaxSize: 64, Action: BodySizeActionPartial, Decompress: true},
			expectPrefixOf:  long,
			expectTruncated: true,
		},
		{
			name:       "invalid data – inspected as-is",
			body:       payload,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "plain text sent as deflate – inspected as-is",
			body:       payload,
			encoding:   []string{"deflate"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "raw deflate – inspected as-is",
			body:       rawDeflate,
			encoding:   []string{"deflate"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: rawDeflate,
		},
		{
			name:       "gzip with trailing data – inspected as-is",
			body:       gzTrailing,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzTrailing,
		},
		{
			name:       "zlib with trailing data – inspected as-is",
			body:       zlibTrailing,
			encoding:   []string{"deflate"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: zlibTrailing,
		},
		{
			name:       "gzip with several members – inspected as-is",
			body:       gzMultiMember,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzMultiMember,
		},
		{
			name:       "gzip header name field – inspected as-is",
			body:       gzNamed,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzNamed,
		},
		{
			name:       "gzip with bad checksum – inspected as-is",
			body:       gzBadCRC,
			encoding:   []string{"gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzBadCRC,
		},
		{
			name:       "stacked, inner layer invalid – original body inspected",
			body:       gzOfPlain,
			encoding:   []string{"deflate, gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzOfPlain,
		},
		{
			name:       "unsupported encoding – inspected as-is",
			body:       payload,
			encoding:   []string{"br"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: payload,
		},
		{
			name:       "too many encodings – inspected as-is",
			body:       gzPayload,
			encoding:   []string{"gzip", "gzip", "gzip", "gzip"},
			settings:   BodySettings{MaxSize: 1024, Decompress: true},
			expectBody: gzPayload,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := makeTestRequest(t, test.body)
			r.Header["Content-Encoding"] = test.encoding

			parsed, err := NewParsedRequestFromRequest(r, logger, test.settings)
			require.NoError(t, err)

			require.Equal(t, test.expectTruncated, parsed.BodyTruncated)
			require.Equal(t, test.expectExceeded, parsed.BodySizeExceeded)
			require.LessOrEqual(t, int64(len(parsed.Body)), test.settings.MaxSize)

			if test.expectPrefixOf != nil {
				require.NotEmpty(t, parsed.Body)
				require.True(t, bytes.HasPrefix(test.expectPrefixOf, parsed.Body))
			} else {
				require.Equal(t, test.expectBody, parsed.Body)
			}

			hb, err := io.ReadAll(parsed.HTTPRequest.Body)
			require.NoError(t, err)
			require.Equal(t, parsed.Body, nilIfEmpty(hb))
		})
	}
}

// The limit must bound decompression itself, not just trim its output afterwards.
func TestDecompressBodyMemoryBounded(t *testing.T) {
	logger := log.WithField("test", "body-decompress")
	bomb := compressGzip(t, make([]byte, 256<<20))

	for _, action := range []string{BodySizeActionDrop, BodySizeActionPartial, BodySizeActionAllow} {
		t.Run(action, func(t *testing.T) {
			r := makeTestRequest(t, bomb)
			r.Header.Set("Content-Encoding", "gzip")

			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)

			_, err := NewParsedRequestFromRequest(r, logger, BodySettings{MaxSize: 1 << 20, Action: action, Decompress: true})
			require.NoError(t, err)

			runtime.ReadMemStats(&after)
			require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(32<<20))
		})
	}
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}

	return b
}

func TestNewParsedRequestFromRequestRemoteAddr(t *testing.T) {
	logger := log.WithField("test", "remote-addr")

	tests := []struct {
		name             string
		remoteAddr       string
		expectNormalized string
	}{
		{name: "tcp ipv4", remoteAddr: "1.2.3.4:1234", expectNormalized: "1.2.3.4"},
		{name: "tcp ipv6", remoteAddr: "[::1]:1234", expectNormalized: "::1"},
		{name: "unix socket linux", remoteAddr: "@", expectNormalized: "127.0.0.1"},
		{name: "unix socket freebsd", remoteAddr: "", expectNormalized: "127.0.0.1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := makeTestRequest(t, nil)
			r.RemoteAddr = test.remoteAddr

			parsed, err := NewParsedRequestFromRequest(r, logger, BodySettings{})
			require.NoError(t, err)

			require.Equal(t, test.expectNormalized, parsed.RemoteAddrNormalized)
			require.Equal(t, "1.2.3.4", parsed.ClientIP)
		})
	}
}
