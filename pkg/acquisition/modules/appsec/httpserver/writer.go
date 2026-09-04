package httpserver

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// responseWriter is a minimal http.ResponseWriter that buffers the response
// body in memory and emits a single HTTP/1.x message on flush. Body buffering
// is fine for the appsec handler — responses are small JSON blobs.
//
// It implements SetReadDeadline / SetWriteDeadline so the existing handler can
// keep using http.NewResponseController(rw).SetReadDeadline(...) to bound the
// body read.
type responseWriter struct {
	conn       net.Conn
	bw         *bufio.Writer
	header     http.Header // lazy: nil until Header() is called
	body       bytes.Buffer
	status     int
	headerSent bool
	proto      string
	closeConn  bool
}

func newResponseWriter(conn net.Conn, bw *bufio.Writer, proto string) *responseWriter {
	if proto != "HTTP/1.0" {
		proto = "HTTP/1.1"
	}
	return &responseWriter{
		conn:  conn,
		bw:    bw,
		proto: proto,
	}
}

func (w *responseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header, 4)
	}
	return w.header
}

// WriteHeader records the status code. Codes outside the range a status line
// can carry are coerced to 500: net/http panics on those, and taking down the
// appsec listener because a hub config carries a bad user_blocked_http_code is
// worse than answering 500.
func (w *responseWriter) WriteHeader(code int) {
	if w.headerSent {
		return
	}
	if code < 100 || code > 999 {
		code = http.StatusInternalServerError
	}
	w.status = code
	w.headerSent = true
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.headerSent {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

// SetReadDeadline lets http.NewResponseController set a body-read deadline.
func (w *responseWriter) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

// SetWriteDeadline mirrors SetReadDeadline for completeness.
func (w *responseWriter) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// flush writes the status line, headers, and buffered body to the connection.
// Server-controlled headers (Content-Length, Connection) are written directly
// to avoid map operations; handler-set duplicates are skipped.
//
//nolint:errcheck // bufio.Writer retains the first write error and returns it from Flush.
func (w *responseWriter) flush() error {
	if !w.headerSent {
		w.WriteHeader(http.StatusOK)
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	bw := w.bw
	var nbuf [20]byte

	bw.WriteString(w.proto)
	bw.WriteByte(' ')
	bw.Write(strconv.AppendInt(nbuf[:0], int64(status), 10))
	bw.WriteByte(' ')
	reason := http.StatusText(status)
	if reason == "" {
		reason = "status"
	}
	bw.WriteString(reason)
	bw.WriteString("\r\n")

	// A 1xx/204/304 response carries no body, so a Content-Length would leave
	// the client reading our JSON as the start of the next response.
	withBody := bodyAllowedForStatus(status)
	if withBody {
		bw.WriteString("Content-Length: ")
		bw.Write(strconv.AppendInt(nbuf[:0], int64(w.body.Len()), 10))
		bw.WriteString("\r\n")
	}
	if w.closeConn {
		bw.WriteString("Connection: close\r\n")
	}
	for name, vals := range w.header {
		if reservedResponseHeader(name) {
			continue
		}
		// A name that isn't a token, or a value carrying CR/LF, would let a
		// handler emit a second response message on the same connection.
		if !isValidHeaderName([]byte(name)) {
			continue
		}
		for _, v := range vals {
			bw.WriteString(name)
			bw.WriteString(": ")
			bw.WriteString(sanitizeHeaderValue(v))
			bw.WriteString("\r\n")
		}
	}
	bw.WriteString("\r\n")
	if withBody {
		bw.Write(w.body.Bytes())
	}
	return bw.Flush()
}

// bodyAllowedForStatus mirrors net/http: these statuses are defined to have no
// message body.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}

	return true
}

// reservedResponseHeader reports whether the server frames this header itself.
// The comparison is case-insensitive: a handler writing straight into the map
// bypasses http.Header.Set's canonicalization, and a second Content-Length is
// enough to desync a client.
func reservedResponseHeader(name string) bool {
	return strings.EqualFold(name, "Content-Length") ||
		strings.EqualFold(name, "Connection") ||
		strings.EqualFold(name, "Transfer-Encoding") ||
		strings.EqualFold(name, "Date")
}

// sanitizeHeaderValue replaces every byte a header value cannot carry with a
// space. CR and LF would let a handler split the response into two messages;
// the other control bytes make strict clients — net/http's own included —
// reject the whole response.
func sanitizeHeaderValue(v string) string {
	i := 0
	for ; i < len(v); i++ {
		if !validHeaderValueByte(v[i]) {
			break
		}
	}

	if i == len(v) {
		return v
	}

	b := []byte(v)
	for ; i < len(b); i++ {
		if !validHeaderValueByte(b[i]) {
			b[i] = ' '
		}
	}

	return string(b)
}

func validHeaderValueByte(c byte) bool {
	return c == '\t' || (c >= 0x20 && c != 0x7f)
}
