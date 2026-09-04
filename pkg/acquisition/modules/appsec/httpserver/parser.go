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

// readLine reads bytes through the next \n. The terminating \r\n or bare \n is
// stripped from the returned slice. Returns io.EOF only when no bytes were read.
//
// The returned slice aliases the bufio.Reader's internal buffer and is only
// valid until the next read from r. Callers that need to retain bytes across
// further reads must copy them (e.g. via string(line) when storing in a map).
//
// The bufio.Reader's buffer must be sized to hold the longest acceptable line;
// callers configure this via bufio.NewReaderSize.
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

// requestLine holds the parsed components of an HTTP request line.
type requestLine struct {
	Method     string
	Target     string
	Proto      string
	ProtoMajor int
	ProtoMinor int
}

// readRequestLine reads and parses "METHOD SP URI SP HTTP/X.Y" from r.
// Lenient: skips leading blank lines, accepts any non-SP/CR/LF bytes in URI,
// records the proto string even when its format is unrecognized.
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

// readHeaders reads header lines until an empty line. Lenient: any byte except
// CR/LF is allowed in values (including control chars). Invalid names (non-token
// bytes) are skipped silently.
//
// Obsolete line folding is joined into the preceding value with a single space,
// the way net/http does it: dropping the continuation would hide bytes from the
// appsec engine that the protected application still sees.
func readHeaders(r *bufio.Reader, limits Limits) (http.Header, error) {
	limits = limits.withDefaults()
	// Pre-size to a typical header count to avoid map growth allocations.
	h := make(http.Header, 16)
	totalBytes := 0
	count := 0

	// A continuation line rewrites the value already stored for lastName. The
	// buffer is only touched when a fold actually shows up, and accumulating
	// into it keeps a run of continuations linear rather than quadratic.
	var (
		lastName string
		folded   []byte
		folding  bool
	)

	// Leading whitespace is stripped once the folded value is complete, not
	// per line: that is what net/http does, and the difference shows when a
	// continuation line is empty.
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
			return nil, err
		}
		if len(line) == 0 {
			endFold()
			return h, nil
		}
		totalBytes += len(line) + 2
		if totalBytes > limits.MaxHeaderBytes {
			return nil, ErrHeadersTooLarge
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
			return nil, ErrTooManyHeaders
		}
		lastName = name
		h[name] = append(h[name], string(trimOWS(line[colon+1:])))
	}
}

// trimOWS strips optional leading and trailing whitespace (RFC 7230 OWS).
func trimOWS(b []byte) []byte {
	return bytes.TrimRight(bytes.TrimLeft(b, " \t"), " \t")
}

// canonicalHeaderName mirrors net/textproto, including its deliberate tolerance
// for a space before the colon (go.dev/issue/34540); such a name is kept
// verbatim rather than canonicalized. Rejecting "X-Evil : payload" outright
// would hide the value from the appsec engine while origins that tolerate it
// still act on the header.
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

// isTokenByte reports whether b is a valid RFC 7230 token byte.
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
