package httpserver

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
	if rl.Method != http.MethodGet || rl.Target != "/foo" || rl.Proto != "HTTP/1.1" {
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
	if rl.Method != http.MethodPost || rl.Target != "/a" {
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
	h, _, err := readHeaders(r, Limits{})
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
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if got := h.Get("X-Evil"); got != "ab\x01cd\x7fef" {
		t.Errorf("value lost control chars: got %q", got)
	}
}

func TestReadHeaders_BareLF(t *testing.T) {
	r := bufReader("A: 1\nB: 2\n\n")
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("A") != "1" || h.Get("B") != "2" {
		t.Errorf("got %v", h)
	}
}

func TestReadHeaders_MultipleValues(t *testing.T) {
	r := bufReader("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if got := h.Values("Set-Cookie"); len(got) != 2 || got[0] != "a=1" || got[1] != "b=2" {
		t.Errorf("got %v", got)
	}
}

func TestReadHeaders_SkipInvalidName(t *testing.T) {
	// A NUL is not a token byte and not the space net/textproto tolerates.
	r := bufReader("X\x00Foo: bad\r\nX-Good: ok\r\n\r\n")
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("X-Good") != "ok" {
		t.Errorf("X-Good missing: %v", h)
	}
	if h.Get("X\x00Foo") != "" {
		t.Error("invalid header should have been dropped")
	}
}

// A space before the colon is kept, uncanonicalized, the way net/http does it:
// the appsec engine has to see any header an origin might act on.
func TestReadHeaders_SpaceBeforeColon(t *testing.T) {
	r := bufReader("X-Evil : payload\r\n\r\n")
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if got := h["X-Evil "]; len(got) != 1 || got[0] != "payload" {
		t.Errorf("got %v, want [payload] under the verbatim name", h)
	}
}

func TestReadHeaders_ObsFold(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   string
		want  string
	}{
		{"single continuation", "X-Foo: a\r\n b\r\n\r\n", "X-Foo", "a b"},
		{"tab continuation", "X-Foo: a\r\n\tb\r\n\r\n", "X-Foo", "a b"},
		{"two continuations", "X-Foo: a\r\n b\r\n  c\r\n\r\n", "X-Foo", "a b c"},
		{"fold does not leak into next header", "X-Foo: a\r\n b\r\nX-Bar: c\r\n\r\n", "X-Bar", "c"},
		{"leading fold has nothing to fold into", " orphan\r\nX-Foo: a\r\n\r\n", "X-Foo", "a"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _, err := readHeaders(bufReader(tc.input), Limits{})
			if err != nil {
				t.Fatalf("readHeaders: %v", err)
			}
			if got := h.Get(tc.key); got != tc.want {
				t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
			}
		})
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
	if _, _, err := readHeaders(r, Limits{MaxHeaderCount: 100}); !errors.Is(err, ErrTooManyHeaders) {
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
	if _, _, err := readHeaders(r, Limits{MaxHeaderBytes: 64}); !errors.Is(err, ErrHeadersTooLarge) {
		t.Errorf("got err=%v, want ErrHeadersTooLarge", err)
	}
}

func TestReadHeaders_TrimsOWS(t *testing.T) {
	r := bufReader("X-Foo:   bar  \r\n\r\n")
	h, _, err := readHeaders(r, Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}
	if h.Get("X-Foo") != "bar" {
		t.Errorf("got %q, want %q", h.Get("X-Foo"), "bar")
	}
}

func TestParseHTTPVersion(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		ok           bool
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
		major, minor, ok := parseHTTPVersion(c.in)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("parseHTTPVersion(%q) = (%d, %d, %v), want (%d, %d, %v)", c.in, major, minor, ok, c.major, c.minor, c.ok)
		}
	}
}

// A long run of continuation lines must stay linear: folding by rewriting the
// stored string each time would be quadratic and DoS-able within MaxHeaderBytes.
func TestReadHeaders_ManyFolds(t *testing.T) {
	var b strings.Builder

	b.WriteString("X-Foo: a\r\n")

	for range 20000 {
		b.WriteString(" b\r\n")
	}

	b.WriteString("\r\n")

	h, _, err := readHeaders(bufReader(b.String()), Limits{})
	if err != nil {
		t.Fatalf("readHeaders: %v", err)
	}

	if got, want := len(h.Get("X-Foo")), 1+20000*2; got != want {
		t.Errorf("folded value length = %d, want %d", got, want)
	}
}

func TestReadHeaders_Order(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "wire order, not map order",
			input: "Zeta: 1\r\nAlpha: 2\r\nMiddle: 3\r\n\r\n",
			want:  []string{"Zeta", "Alpha", "Middle"},
		},
		{
			name:  "a repeated header appears once per line",
			input: "Accept: a\r\nHost: x\r\nAccept: b\r\n\r\n",
			want:  []string{"Accept", "Host", "Accept"},
		},
		{
			name:  "a folded value does not add an entry",
			input: "X-Fold: a\r\n b\r\nHost: x\r\n\r\n",
			want:  []string{"X-Fold", "Host"},
		},
		{
			name:  "a dropped header line is not recorded",
			input: "X\x00Bad: 1\r\nnocolon\r\nHost: x\r\n\r\n",
			want:  []string{"Host"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, order, err := readHeaders(bufReader(tc.input), Limits{})
			require.NoError(t, err)
			require.Equal(t, tc.want, order)
		})
	}
}
