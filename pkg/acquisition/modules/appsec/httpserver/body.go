package httpserver

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	errInvalidContentLength     = errors.New("invalid Content-Length")
	errConflictingContentLength = errors.New("conflicting Content-Length headers")
	errMalformedChunkSize       = errors.New("malformed chunk size")
	errMalformedChunk           = errors.New("missing CRLF after chunk data")
)

// bodyInfo describes how the request body is framed on the wire.
type bodyInfo struct {
	Body             io.ReadCloser
	ContentLength    int64
	TransferEncoding []string
	Chunked          bool
}

// newBodyReader frames the body exactly like net/http: a WAF that disagrees
// with the origin on where the body ends enables smuggling. The caller must
// drain a chunked body's trailer section.
func newBodyReader(src *bufio.Reader, headers http.Header, major, minor int) (bodyInfo, error) {
	var te []string
	// Ignored below HTTP/1.1, golang/go#12785.
	if major > 1 || (major == 1 && minor >= 1) {
		te = parseTransferEncoding(headers.Get("Transfer-Encoding"))
	}

	chunked := len(te) > 0 && te[len(te)-1] == "chunked"
	if chunked {
		// RFC 7230 §3.3.3: chunked wins over Content-Length.
		headers.Del("Content-Length")
		return bodyInfo{
			Body:             &chunkedBody{r: newChunkedReader(src)},
			ContentLength:    -1,
			TransferEncoding: te,
			Chunked:          true,
		}, nil
	}

	cls := headers.Values("Content-Length")
	if len(cls) == 0 {
		return bodyInfo{
			Body:             http.NoBody,
			ContentLength:    0,
			TransferEncoding: te,
		}, nil
	}

	first := strings.TrimSpace(cls[0])
	for _, cl := range cls[1:] {
		if strings.TrimSpace(cl) != first {
			return bodyInfo{}, errConflictingContentLength
		}
	}

	// ParseUint with 63 bits rejects a leading sign, which origins disagree
	// on; net/http does the same.
	cl, err := strconv.ParseUint(first, 10, 63)
	if err != nil {
		return bodyInfo{}, errInvalidContentLength
	}

	if cl == 0 {
		return bodyInfo{
			Body:             http.NoBody,
			ContentLength:    0,
			TransferEncoding: te,
		}, nil
	}

	return bodyInfo{
		Body:             &fixedBody{r: src, remaining: int64(cl)},
		ContentLength:    int64(cl),
		TransferEncoding: te,
	}, nil
}

// fixedBody saves the allocations of io.NopCloser(io.LimitReader(...)).
type fixedBody struct {
	r         *bufio.Reader
	remaining int64
}

func (b *fixedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	if err == io.EOF && b.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (*fixedBody) Close() error { return nil }

// chunkedBody saves the allocation of io.NopCloser.
type chunkedBody struct{ r *chunkedReader }

func (b *chunkedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (*chunkedBody) Close() error                 { return nil }

func parseTransferEncoding(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// chunkedReader decodes a chunked body up to the terminating zero-size chunk,
// leaving the trailer section unread.
type chunkedReader struct {
	r         *bufio.Reader
	remaining int64
	eof       bool
}

// maxChunkSizeLine matches net/http's limit on a chunk size line, extensions
// included: a shorter one would reject bodies the origin accepts.
const maxChunkSizeLine = 4096

func newChunkedReader(r *bufio.Reader) *chunkedReader {
	return &chunkedReader{r: r}
}

func (cr *chunkedReader) Read(p []byte) (int, error) {
	if cr.eof {
		return 0, io.EOF
	}
	if cr.remaining == 0 {
		size, err := cr.readChunkSize()
		if err != nil {
			return 0, err
		}
		if size == 0 {
			cr.eof = true
			return 0, io.EOF
		}
		cr.remaining = size
	}
	toRead := min(int64(len(p)), cr.remaining)
	n, err := cr.r.Read(p[:toRead])
	cr.remaining -= int64(n)
	if err != nil {
		return n, err
	}
	if cr.remaining == 0 {
		if err := readCRLF(cr.r); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (cr *chunkedReader) readChunkSize() (int64, error) {
	line, err := readLine(cr.r, maxChunkSizeLine)
	if err != nil {
		return 0, err
	}
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return 0, errMalformedChunkSize
	}
	size, err := strconv.ParseInt(string(line), 16, 64)
	if err != nil || size < 0 {
		return 0, fmt.Errorf("%w: %q", errMalformedChunkSize, line)
	}
	return size, nil
}

func readCRLF(r *bufio.Reader) error {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return err
	}
	if buf[0] != '\r' || buf[1] != '\n' {
		return errMalformedChunk
	}
	return nil
}
