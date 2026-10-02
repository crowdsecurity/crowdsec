package httpserver

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

var (
	ErrLineTooLong          = errors.New("line too long")
	ErrHeadersTooLarge      = errors.New("headers too large")
	ErrTooManyHeaders       = errors.New("too many headers")
	ErrMalformedRequestLine = errors.New("malformed request line")
)

const (
	DefaultMaxLineSize    = 16 * 1024
	DefaultMaxHeaderBytes = 1 * 1024 * 1024
	DefaultMaxHeaderCount = 128
)

// Limits bounds parser memory usage. Zero fields fall back to the package defaults.
type Limits struct {
	MaxLineSize    int
	MaxHeaderBytes int
	MaxHeaderCount int
}

func (l Limits) withDefaults() Limits {
	if l.MaxLineSize <= 0 {
		l.MaxLineSize = DefaultMaxLineSize
	}
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if l.MaxHeaderCount <= 0 {
		l.MaxHeaderCount = DefaultMaxHeaderCount
	}
	return l
}

// readLine returns the next line without its \r\n or \n; io.EOF means nothing
// was read. The slice aliases r's buffer (copy it to keep it past the next read),
// and that buffer must be sized for the longest acceptable line.
func readLine(r *bufio.Reader, maxSize int) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, ErrLineTooLong
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if len(line) > maxSize+1 {
		return nil, ErrLineTooLong
	}
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, nil
}

type requestLine struct {
	Method     string
	Target     string
	Proto      string
	ProtoMajor int
	ProtoMinor int
}

// readRequestLine is lenient: it skips leading blank lines, accepts any byte in
// the target, and keeps an unrecognized proto (with a zero version).
func readRequestLine(r *bufio.Reader, maxLine int) (requestLine, error) {
	var (
		line []byte
		err  error
	)
	for {
		line, err = readLine(r, maxLine)
		if err != nil {
			return requestLine{}, err
		}
		if len(line) > 0 {
			break
		}
	}
	first := bytes.IndexByte(line, ' ')
	if first <= 0 {
		return requestLine{}, fmt.Errorf("%w: %q", ErrMalformedRequestLine, line)
	}
	rest := line[first+1:]
	last := bytes.LastIndexByte(rest, ' ')
	if last <= 0 {
		return requestLine{}, fmt.Errorf("%w: %q", ErrMalformedRequestLine, line)
	}
	rl := requestLine{
		Method: string(line[:first]),
		Target: string(rest[:last]),
		Proto:  string(rest[last+1:]),
	}
	if major, minor, ok := parseHTTPVersion(rl.Proto); ok {
		rl.ProtoMajor = major
		rl.ProtoMinor = minor
	}
	return rl, nil
}

func parseHTTPVersion(proto string) (major, minor int, ok bool) {
	rest, found := strings.CutPrefix(proto, "HTTP/")
	if !found {
		return 0, 0, false
	}
	majorStr, minorStr, found := strings.Cut(rest, ".")
	if !found {
		return 0, 0, false
	}
	m, err := strconv.Atoi(majorStr)
	if err != nil || m < 0 {
		return 0, 0, false
	}
	n, err := strconv.Atoi(minorStr)
	if err != nil || n < 0 {
		return 0, 0, false
	}
	return m, n, true
}

// readHeaders keeps control bytes in values and skips invalid names rather than
// failing, so the WAF sees what the origin might. Folded lines are joined with a
// space, as net/http does. It also returns the names in wire order, for JA4H.
func readHeaders(r *bufio.Reader, limits Limits) (http.Header, []string, error) {
	limits = limits.withDefaults()
	h := make(http.Header, 16)
	order := make([]string, 0, 16)
	totalBytes := 0
	count := 0

	// Folds accumulate in a buffer so a long run of them stays linear.
	var (
		lastName string
		folded   []byte
		folding  bool
	)

	// Trim once the fold is complete, not per line, like net/http: it differs
	// when a continuation line is empty.
	endFold := func() {
		if !folding {
			return
		}
		vals := h[lastName]
		vals[len(vals)-1] = string(bytes.TrimLeft(folded, " \t"))
		folding = false
	}

	for {
		line, err := readLine(r, limits.MaxLineSize)
		if err != nil {
			return nil, nil, err
		}
		if len(line) == 0 {
			endFold()
			return h, order, nil
		}
		totalBytes += len(line) + 2
		if totalBytes > limits.MaxHeaderBytes {
			return nil, nil, ErrHeadersTooLarge
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastName == "" {
				continue // a fold with no header to fold into
			}
			if !folding {
				vals := h[lastName]
				folded = append(folded[:0], vals[len(vals)-1]...)
				folding = true
			}
			folded = append(folded, ' ')
			folded = append(folded, trimOWS(line)...)
			continue
		}
		endFold()
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name, ok := canonicalHeaderName(line[:colon])
		if !ok {
			continue
		}
		count++
		if count > limits.MaxHeaderCount {
			return nil, nil, ErrTooManyHeaders
		}
		lastName = name
		h[name] = append(h[name], string(trimOWS(line[colon+1:])))
		order = append(order, name)
	}
}

// trimOWS strips optional leading and trailing whitespace (RFC 7230 OWS).
func trimOWS(b []byte) []byte {
	return bytes.TrimRight(bytes.TrimLeft(b, " \t"), " \t")
}

// canonicalHeaderName mirrors net/textproto, which keeps a name with a space
// before the colon verbatim (go.dev/issue/34540): origins may act on it.
func canonicalHeaderName(name []byte) (string, bool) {
	if len(name) == 0 {
		return "", false
	}

	spaced := false

	for _, b := range name {
		switch {
		case isTokenByte(b):
		case b == ' ':
			spaced = true
		default:
			return "", false
		}
	}

	if spaced {
		return string(name), true
	}

	return textproto.CanonicalMIMEHeaderKey(string(name)), true
}

// isValidHeaderName reports whether name is a bare RFC 7230 token. Used on the
// response side, where we are the one framing the message and can be strict.
func isValidHeaderName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if !isTokenByte(b) {
			return false
		}
	}
	return true
}

// isTokenByte reports whether b is an RFC 7230 token byte.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z',
		b >= 'A' && b <= 'Z',
		b >= '0' && b <= '9':
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}
