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
	errInvalidContentLength = errors.New("invalid Content-Length")
	errMalformedChunkSize   = errors.New("malformed chunk size")
	errMalformedChunk       = errors.New("missing CRLF after chunk data")
)

// bodyInfo describes how the request body is framed on the wire.
type bodyInfo struct {
	Body             io.ReadCloser
	ContentLength    int64
	TransferEncoding []string
	Chunked          bool
}

// newBodyReader builds an io.ReadCloser bounded by Transfer-Encoding /
// Content-Length so the server never relies on the connection EOF for framing.
//
// If both Transfer-Encoding: chunked and Content-Length are present, chunked
// wins (per RFC 7230 §3.3.3) and Content-Length is dropped. When chunked is
// used, the returned reader does NOT consume the trailer section — the caller
// must drain it before reading the next request.
func newBodyReader(src *bufio.Reader, headers http.Header) (bodyInfo, error) {
	te := parseTransferEncoding(headers.Get("Transfer-Encoding"))
	chunked := len(te) > 0 && te[len(te)-1] == "chunked"
	if chunked {
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
	cl, err := strconv.ParseInt(strings.TrimSpace(cls[0]), 10, 64)
	if err != nil || cl < 0 {
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
		Body:             &fixedBody{r: src, remaining: cl},
		ContentLength:    cl,
		TransferEncoding: te,
	}, nil
}

// fixedBody is a Content-Length bounded ReadCloser. It replaces the
// io.NopCloser(io.LimitReader(...)) chain with a single allocation.
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

func (b *fixedBody) Close() error { return nil }

// chunkedBody wraps a chunkedReader in an io.ReadCloser without allocating an
// io.NopCloser indirection.
type chunkedBody struct{ r *chunkedReader }

func (b *chunkedBody) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b *chunkedBody) Close() error               { return nil }

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

// chunkedReader decodes RFC 7230 chunked transfer-encoding. It returns io.EOF
// when the zero-length terminator chunk is seen. The trailer section (optional
// trailer headers + final CRLF) is NOT consumed.
type chunkedReader struct {
	r         *bufio.Reader
	remaining int64
	eof       bool
}

const maxChunkSizeLine = 256

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
