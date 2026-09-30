package httpserver

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func bufReader(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		max     int
		want    string
		wantErr error
	}{
		{name: "CRLF", input: "hello\r\n", max: 1024, want: "hello"},
		{name: "bare LF", input: "hello\n", max: 1024, want: "hello"},
		{name: "empty line", input: "\r\n", max: 1024, want: ""},
		{name: "too long", input: "xxxxxxxxxxxxxxxx\r\n", max: 4, wantErr: ErrLineTooLong},
		{name: "EOF without data", input: "", max: 1024, wantErr: io.EOF},
		{name: "EOF mid-line", input: "partial", max: 1024, wantErr: io.ErrUnexpectedEOF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readLine(bufReader(tc.input), tc.max)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

func TestReadRequestLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    requestLine
		wantErr error
	}{
		{
			name:  "standard",
			input: "GET /foo HTTP/1.1\r\n",
			want:  requestLine{Method: http.MethodGet, Target: "/foo", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1},
		},
		{
			name:  "leading blank lines are skipped",
			input: "\r\n\r\nPOST /a HTTP/1.0\r\n",
			want:  requestLine{Method: http.MethodPost, Target: "/a", Proto: "HTTP/1.0", ProtoMajor: 1, ProtoMinor: 0},
		},
		{
			// net/http rejects this; the WAF must still see it.
			name:  "control byte in target",
			input: "GET /foo\x01bar HTTP/1.1\r\n",
			want:  requestLine{Method: http.MethodGet, Target: "/foo\x01bar", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1},
		},
		{
			name:  "unknown proto has zero version",
			input: "GET / WAT/9.9\r\n",
			want:  requestLine{Method: http.MethodGet, Target: "/", Proto: "WAT/9.9"},
		},
		{name: "method only", input: "GET\r\n", wantErr: ErrMalformedRequestLine},
		{name: "no method", input: "  HTTP/1.1\r\n", wantErr: ErrMalformedRequestLine},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readRequestLine(bufReader(tc.input), 1024)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestReadHeaders(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  http.Header
	}{
		{
			name:  "basic",
			input: "Host: example\r\nX-Foo: bar\r\n\r\n",
			want:  http.Header{"Host": {"example"}, "X-Foo": {"bar"}},
		},
		{
			name:  "bare LF",
			input: "A: 1\nB: 2\n\n",
			want:  http.Header{"A": {"1"}, "B": {"2"}},
		},
		{
			name:  "optional whitespace is trimmed",
			input: "X-Foo:   bar  \r\n\r\n",
			want:  http.Header{"X-Foo": {"bar"}},
		},
		{
			name:  "repeated header keeps every value",
			input: "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n",
			want:  http.Header{"Set-Cookie": {"a=1", "b=2"}},
		},
		{
			// net/http rejects this with a 400; the WAF must still see it.
			name:  "control chars in value are kept",
			input: "X-Evil: ab\x01cd\x7fef\r\n\r\n",
			want:  http.Header{"X-Evil": {"ab\x01cd\x7fef"}},
		},
		{
			name:  "invalid name is dropped",
			input: "X\x00Foo: bad\r\nX-Good: ok\r\n\r\n",
			want:  http.Header{"X-Good": {"ok"}},
		},
		{
			// Kept verbatim like net/http does: the origin might act on it.
			name:  "space before colon",
			input: "X-Evil : payload\r\n\r\n",
			want:  http.Header{"X-Evil ": {"payload"}},
		},
		{
			name:  "obs-fold with space",
			input: "X-Foo: a\r\n b\r\n\r\n",
			want:  http.Header{"X-Foo": {"a b"}},
		},
		{
			name:  "obs-fold with tab",
			input: "X-Foo: a\r\n\tb\r\n\r\n",
			want:  http.Header{"X-Foo": {"a b"}},
		},
		{
			name:  "two obs-folds",
			input: "X-Foo: a\r\n b\r\n  c\r\n\r\n",
			want:  http.Header{"X-Foo": {"a b c"}},
		},
		{
			name:  "obs-fold does not leak into next header",
			input: "X-Foo: a\r\n b\r\nX-Bar: c\r\n\r\n",
			want:  http.Header{"X-Foo": {"a b"}, "X-Bar": {"c"}},
		},
		{
			name:  "leading obs-fold has nothing to fold into",
			input: " orphan\r\nX-Foo: a\r\n\r\n",
			want:  http.Header{"X-Foo": {"a"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := readHeaders(bufReader(tc.input), Limits{})
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestReadHeaders_Limits(t *testing.T) {
	var tooMany strings.Builder
	for i := range 130 {
		fmt.Fprintf(&tooMany, "X-H%c: v\r\n", 'a'+i%26)
	}
	tooMany.WriteString("\r\n")

	tooLarge := strings.Repeat("X-Foo: "+strings.Repeat("a", 30)+"\r\n", 10) + "\r\n"

	tests := []struct {
		name    string
		input   string
		limits  Limits
		wantErr error
	}{
		{name: "too many headers", input: tooMany.String(), limits: Limits{MaxHeaderCount: 100}, wantErr: ErrTooManyHeaders},
		{name: "headers too large", input: tooLarge, limits: Limits{MaxHeaderBytes: 64}, wantErr: ErrHeadersTooLarge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := readHeaders(bufReader(tc.input), tc.limits)
			require.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// Folding by rewriting the stored value on each continuation would be
// quadratic, and DoS-able within MaxHeaderBytes.
func TestReadHeaders_ManyFolds(t *testing.T) {
	const folds = 20000

	input := "X-Foo: a\r\n" + strings.Repeat(" b\r\n", folds) + "\r\n"

	h, _, err := readHeaders(bufReader(input), Limits{})
	require.NoError(t, err)
	require.Len(t, h.Get("X-Foo"), 1+folds*2)
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

func TestParseHTTPVersion(t *testing.T) {
	tests := []struct {
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

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			major, minor, ok := parseHTTPVersion(tc.in)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.major, major)
			require.Equal(t, tc.minor, minor)
		})
	}
}
