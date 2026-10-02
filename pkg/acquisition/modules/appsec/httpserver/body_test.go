package httpserver

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBodyReader(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		minor       int // HTTP/1.x
		input       string
		wantErr     error
		wantLength  int64
		wantChunked bool
		wantBody    string
		wantHeaders http.Header // headers after the call, when checked
	}{
		{
			name:       "content-length",
			headers:    http.Header{"Content-Length": {"12"}},
			minor:      1,
			input:      "hello, world",
			wantLength: 12,
			wantBody:   "hello, world",
		},
		{
			name:    "no body",
			headers: http.Header{},
			minor:   1,
		},
		{
			name:        "chunked",
			headers:     http.Header{"Transfer-Encoding": {"chunked"}},
			minor:       1,
			input:       "4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n",
			wantLength:  -1,
			wantChunked: true,
			wantBody:    "Wikipedia in \r\n\r\nchunks.",
		},
		{
			// RFC 7230 §3.3.3: chunked wins and Content-Length is removed.
			name:        "chunked drops content-length",
			headers:     http.Header{"Transfer-Encoding": {"chunked"}, "Content-Length": {"42"}},
			minor:       1,
			input:       "0\r\n\r\n",
			wantLength:  -1,
			wantChunked: true,
			wantHeaders: http.Header{"Transfer-Encoding": {"chunked"}},
		},
		{
			// net/http ignores Transfer-Encoding below HTTP/1.1 (golang/go#12785);
			// framing the body differently from the origin enables smuggling.
			name:    "chunked ignored on HTTP/1.0",
			headers: http.Header{"Transfer-Encoding": {"chunked"}},
			minor:   0,
			input:   "4\r\nbody\r\n0\r\n\r\n",
		},
		{
			name:       "duplicate content-length that agrees",
			headers:    http.Header{"Content-Length": {"4", " 4 "}},
			minor:      1,
			input:      "body",
			wantLength: 4,
			wantBody:   "body",
		},
		{
			name:    "conflicting content-length",
			headers: http.Header{"Content-Length": {"4", "40"}},
			minor:   1,
			input:   "bodyGET /smuggled HTTP/1.1\r\n\r\n",
			wantErr: errConflictingContentLength,
		},
		{
			name:    "non-numeric content-length",
			headers: http.Header{"Content-Length": {"abc"}},
			minor:   1,
			wantErr: errInvalidContentLength,
		},
		{
			name:    "negative content-length",
			headers: http.Header{"Content-Length": {"-1"}},
			minor:   1,
			wantErr: errInvalidContentLength,
		},
		{
			name:    "signed content-length",
			headers: http.Header{"Content-Length": {"+4"}},
			minor:   1,
			input:   "body",
			wantErr: errInvalidContentLength,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := newBodyReader(bufReader(tc.input), tc.headers, 1, tc.minor)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantLength, info.ContentLength)
			require.Equal(t, tc.wantChunked, info.Chunked)

			body, err := io.ReadAll(info.Body)
			require.NoError(t, err)
			require.Equal(t, tc.wantBody, string(body))

			if tc.wantHeaders != nil {
				require.Equal(t, tc.wantHeaders, tc.headers)
			}
		})
	}
}

func TestParseTransferEncoding(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"chunked", []string{"chunked"}},
		{"gzip, chunked", []string{"gzip", "chunked"}},
		{" CHUNKED ", []string{"chunked"}},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, parseTransferEncoding(tc.in))
		})
	}
}

func TestChunkedReader(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		bufSize  int
		wantN    int
		wantBody string
		wantErr  error
	}{
		{
			name:     "chunk extension is ignored",
			input:    "5;name=value\r\nhello\r\n0\r\n\r\n",
			bufSize:  16,
			wantN:    5,
			wantBody: "hello",
		},
		{
			name:    "malformed size",
			input:   "ZZ\r\nhi\r\n0\r\n\r\n",
			bufSize: 16,
			wantErr: errMalformedChunkSize,
		},
		{
			// The chunk data is returned along with the error.
			name:     "missing CRLF after chunk",
			input:    "4\r\ndataNOTCRLF",
			bufSize:  4,
			wantN:    4,
			wantBody: "data",
			wantErr:  errMalformedChunk,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr := newChunkedReader(bufio.NewReader(strings.NewReader(tc.input)))
			buf := make([]byte, tc.bufSize)

			n, err := cr.Read(buf)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}

			require.Equal(t, tc.wantN, n)
			require.Equal(t, tc.wantBody, string(buf[:n]))
		})
	}
}
