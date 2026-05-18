package httpserver

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func bufReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

func TestReadLine_CRLF(t *testing.T) {
	r := bufReader("hello\r\n")
	got, err := readLine(r, 1024)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestReadLine_BareLF(t *testing.T) {
	r := bufReader("hello\n")
	got, err := readLine(r, 1024)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestReadLine_Empty(t *testing.T) {
	r := bufReader("\r\n")
	got, err := readLine(r, 1024)
	if err != nil {
		t.Fatalf("readLine: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want empty", got)
	}
}

func TestReadLine_TooLong(t *testing.T) {
	r := bufReader("xxxxxxxxxxxxxxxx\r\n")
	if _, err := readLine(r, 4); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("got err=%v, want ErrLineTooLong", err)
	}
}

func TestReadLine_EOFNoData(t *testing.T) {
	r := bufReader("")
	if _, err := readLine(r, 1024); !errors.Is(err, io.EOF) {
		t.Errorf("got err=%v, want io.EOF", err)
	}
}

func TestReadLine_UnexpectedEOF(t *testing.T) {
	r := bufReader("partial")
	_, err := readLine(r, 1024)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got err=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadRequestLine_Standard(t *testing.T) {
	r := bufReader("GET /foo HTTP/1.1\r\n")
	rl, err := readRequestLine(r, 1024)
	if err != nil {
		t.Fatalf("readRequestLine: %v", err)
	}
	if rl.Method != "GET" || rl.Target != "/foo" || rl.Proto != "HTTP/1.1" {
		t.Errorf("got %+v", rl)
	}
	if rl.ProtoMajor != 1 || rl.ProtoMinor != 1 {
		t.Errorf("proto version got %d.%d, want 1.1", rl.ProtoMajor, rl.ProtoMinor)
	}
}

func TestReadRequestLine_SkipsBlankLines(t *testing.T) {
	r := bufReader("\r\n\r\nPOST /a HTTP/1.0\r\n")
	rl, err := readRequestLine(r, 1024)
	if err != nil {
		t.Fatalf("readRequestLine: %v", err)
	}
	if rl.Method != "POST" || rl.Target != "/a" {
		t.Errorf("got %+v", rl)
	}
}

func TestReadRequestLine_URIWithWeirdBytes(t *testing.T) {
	// URI contains bytes net/http would reject (e.g. raw 0x01)
	r := bufReader("GET /foo\x01bar HTTP/1.1\r\n")
	rl, err := readRequestLine(r, 1024)
	if err != nil {
		t.Fatalf("readRequestLine: %v", err)
	}
	if rl.Target != "/foo\x01bar" {
		t.Errorf("target got %q, want with embedded \\x01", rl.Target)
	}
}

func TestReadRequestLine_UnknownProto(t *testing.T) {
	r := bufReader("GET / WAT/9.9\r\n")
	rl, err := readRequestLine(r, 1024)
	if err != nil {
		t.Fatalf("readRequestLine: %v", err)
	}
	if rl.Proto != "WAT/9.9" {
		t.Errorf("proto got %q", rl.Proto)
	}
	if rl.ProtoMajor != 0 || rl.ProtoMinor != 0 {
		t.Errorf("expected zero version for unrecognized proto, got %d.%d", rl.ProtoMajor, rl.ProtoMinor)
	}
}

func TestReadRequestLine_Malformed(t *testing.T) {
	for _, in := range []string{
		"GET\r\n",
		"  HTTP/1.1\r\n",
		"GET\r\n",
	} {
		r := bufReader(in)
		if _, err := readRequestLine(r, 1024); !errors.Is(err, ErrMalformedRequestLine) {
			t.Errorf("input %q: got err=%v, want ErrMalformedRequestLine", in, err)
		}
	}
}

func TestReadHeaders_Basic(t *testing.T) {
	r := bufReader("Host: example\r\nX-Foo: bar\r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("Host") != "example" || h.Get("X-Foo") != "bar" {
		t.Errorf("got %v", h)
	}
}

func TestReadHeaders_ControlCharsInValue(t *testing.T) {
	// This is the key acceptance test: header values with control characters
	// must be preserved. net/http would reject this with 400.
	r := bufReader("X-Evil: ab\x01cd\x7fef\r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if got := h.Get("X-Evil"); got != "ab\x01cd\x7fef" {
		t.Errorf("value lost control chars: got %q", got)
	}
}

func TestReadHeaders_BareLF(t *testing.T) {
	r := bufReader("A: 1\nB: 2\n\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("A") != "1" || h.Get("B") != "2" {
		t.Errorf("got %v", h)
	}
}

func TestReadHeaders_MultipleValues(t *testing.T) {
	r := bufReader("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if got := h.Values("Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Errorf("got %v", got)
	}
}

func TestReadHeaders_SkipInvalidName(t *testing.T) {
	// "X Foo" has a space — invalid token. Should be silently dropped.
	r := bufReader("X Foo: bad\r\nX-Good: ok\r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("X-Good") != "ok" {
		t.Errorf("X-Good missing: %v", h)
	}
	if h.Get("X Foo") != "" {
		t.Errorf("invalid header should have been dropped")
	}
}

func TestReadHeaders_DropObsFold(t *testing.T) {
	r := bufReader("X-Foo: a\r\n b\r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("X-Foo") != "a" {
		t.Errorf("got %q, continuation line should have been dropped", h.Get("X-Foo"))
	}
}

func TestReadHeaders_TooMany(t *testing.T) {
	var b strings.Builder
	for i := range 130 {
		b.WriteString("X-H")
		b.WriteByte(byte('a' + i%26))
		b.WriteString(": v\r\n")
	}
	b.WriteString("\r\n")
	r := bufReader(b.String())
	if _, err := readHeaders(r, Limits{MaxHeaderCount: 100}); !errors.Is(err, ErrTooManyHeaders) {
		t.Errorf("got err=%v, want ErrTooManyHeaders", err)
	}
}

func TestReadHeaders_TooLarge(t *testing.T) {
	// 200 bytes of header data with a 64-byte total budget.
	var b strings.Builder
	for range 10 {
		b.WriteString("X-Foo: ")
		b.WriteString(strings.Repeat("a", 30))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	r := bufReader(b.String())
	if _, err := readHeaders(r, Limits{MaxHeaderBytes: 64}); !errors.Is(err, ErrHeadersTooLarge) {
		t.Errorf("got err=%v, want ErrHeadersTooLarge", err)
	}
}

func TestReadHeaders_TrimsOWS(t *testing.T) {
	r := bufReader("X-Foo:   bar  \r\n\r\n")
	h, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("X-Foo") != "bar" {
		t.Errorf("got %q, want %q", h.Get("X-Foo"), "bar")
	}
}

func TestParseHTTPVersion(t *testing.T) {
	cases := []struct {
		in          string
		major, minor int
		ok          bool
	}{
		{"HTTP/1.1", 1, 1, true},
		{"HTTP/1.0", 1, 0, true},
		{"HTTP/2.0", 2, 0, true},
		{"HTTP/9.9", 9, 9, true},
		{"WAT/1.1", 0, 0, false},
		{"HTTP/", 0, 0, false},
		{"HTTP/abc", 0, 0, false},
		{"HTTP/1", 0, 0, false},
	}
	for _, c := range cases {
		maj, min, ok := parseHTTPVersion(c.in)
		if ok != c.ok || maj != c.major || min != c.minor {
			t.Errorf("parseHTTPVersion(%q) = (%d, %d, %v), want (%d, %d, %v)", c.in, maj, min, ok, c.major, c.minor, c.ok)
		}
	}
}
