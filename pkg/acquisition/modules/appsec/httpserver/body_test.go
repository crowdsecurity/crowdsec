package httpserver

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNewBodyReader_ContentLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("hello, world"))
	h := http.Header{"Content-Length": {"12"}}
	info, err := newBodyReader(r, h)
	if err != nil {
		t.Fatalf("newBodyReader: %v", err)
	}
	if info.ContentLength != 12 || info.Chunked {
		t.Errorf("info=%+v", info)
	}
	got, err := io.ReadAll(info.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != "hello, world" {
		t.Errorf("got %q", got)
	}
}

func TestNewBodyReader_NoBody(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	info, err := newBodyReader(r, http.Header{})
	if err != nil {
		t.Fatalf("newBodyReader: %v", err)
	}
	if info.ContentLength != 0 || info.Chunked {
		t.Errorf("info=%+v", info)
	}
	if got, _ := io.ReadAll(info.Body); len(got) != 0 {
		t.Errorf("expected empty body, got %q", got)
	}
}

func TestNewBodyReader_Chunked(t *testing.T) {
	body := "4\r\nWiki\r\n6\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(body))
	h := http.Header{"Transfer-Encoding": {"chunked"}}
	info, err := newBodyReader(r, h)
	if err != nil {
		t.Fatalf("newBodyReader: %v", err)
	}
	if !info.Chunked {
		t.Errorf("expected chunked=true")
	}
	got, err := io.ReadAll(info.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != "Wikipedia in \r\n\r\nchunks." {
		t.Errorf("got %q", got)
	}
}

func TestNewBodyReader_ChunkedDropsContentLength(t *testing.T) {
	// Per RFC 7230 §3.3.3: if both are present, chunked wins and CL is removed.
	r := bufio.NewReader(strings.NewReader("0\r\n\r\n"))
	h := http.Header{
		"Transfer-Encoding": {"chunked"},
		"Content-Length":    {"42"},
	}
	info, err := newBodyReader(r, h)
	if err != nil {
		t.Fatalf("newBodyReader: %v", err)
	}
	if !info.Chunked {
		t.Errorf("expected chunked=true")
	}
	if h.Get("Content-Length") != "" {
		t.Errorf("Content-Length should have been removed: %v", h)
	}
}

func TestNewBodyReader_InvalidContentLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	h := http.Header{"Content-Length": {"abc"}}
	if _, err := newBodyReader(r, h); !errors.Is(err, errInvalidContentLength) {
		t.Errorf("got err=%v, want errInvalidContentLength", err)
	}
}

func TestNewBodyReader_NegativeContentLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	h := http.Header{"Content-Length": {"-1"}}
	if _, err := newBodyReader(r, h); !errors.Is(err, errInvalidContentLength) {
		t.Errorf("got err=%v, want errInvalidContentLength", err)
	}
}

func TestParseTransferEncoding(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"chunked", []string{"chunked"}},
		{"gzip, chunked", []string{"gzip", "chunked"}},
		{" CHUNKED ", []string{"chunked"}},
	}
	for _, c := range cases {
		got := parseTransferEncoding(c.in)
		if len(got) != len(c.want) {
			t.Errorf("parseTransferEncoding(%q) len mismatch: got %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("parseTransferEncoding(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestChunkedReader_MalformedSize(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("ZZ\r\nhi\r\n0\r\n\r\n"))
	cr := newChunkedReader(r)
	buf := make([]byte, 16)
	if _, err := cr.Read(buf); !errors.Is(err, errMalformedChunkSize) {
		t.Errorf("got err=%v, want errMalformedChunkSize", err)
	}
}

func TestChunkedReader_MissingCRLFAfterChunk(t *testing.T) {
	// Chunk says 4 bytes but no CRLF after — should error out at the boundary
	// check, returning the consumed bytes along with the error.
	r := bufio.NewReader(strings.NewReader("4\r\ndataNOTCRLF"))
	cr := newChunkedReader(r)
	buf := make([]byte, 4)
	n, err := cr.Read(buf)
	if n != 4 {
		t.Errorf("got n=%d, want 4", n)
	}
	if !errors.Is(err, errMalformedChunk) {
		t.Errorf("got err=%v, want errMalformedChunk", err)
	}
}

func TestChunkedReader_ChunkExt(t *testing.T) {
	// chunk-size with chunk-ext: "5;name=value\r\nhello\r\n0\r\n\r\n"
	r := bufio.NewReader(strings.NewReader("5;name=value\r\nhello\r\n0\r\n\r\n"))
	cr := newChunkedReader(r)
	got, err := io.ReadAll(cr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
}
