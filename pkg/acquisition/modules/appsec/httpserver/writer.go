package httpserver

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strconv"
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

func (w *responseWriter) WriteHeader(code int) {
	if w.headerSent {
		return
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

	bw.WriteString("Content-Length: ")
	bw.Write(strconv.AppendInt(nbuf[:0], int64(w.body.Len()), 10))
	bw.WriteString("\r\n")
	if w.closeConn {
		bw.WriteString("Connection: close\r\n")
	}
	for name, vals := range w.header {
		if name == "Content-Length" || name == "Connection" || name == "Date" {
			continue
		}
		for _, v := range vals {
			bw.WriteString(name)
			bw.WriteString(": ")
			bw.WriteString(v)
			bw.WriteString("\r\n")
		}
	}
	bw.WriteString("\r\n")
	bw.Write(w.body.Bytes())
	return bw.Flush()
}
