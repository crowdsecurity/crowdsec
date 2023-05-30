package gzip

import (
	"compress/gzip"
	"io"
	"sync"
)

var (
	readerPool sync.Pool
)

// Codec is the implementation of a compress.Codec which supports creating
// readers and writers for kafka messages compressed with gzip.
type Codec struct {
	// The compression level to configure on writers created by this codec.
	// Acceptable values are defined in the standard gzip package.
	//
	// Default to gzip.DefaultCompressionLevel.
	Level int

	writerPool sync.Pool
}

// Code implements the compress.Codec interface.
func (c *Codec) Code() int8 { return 1 }

// Name implements the compress.Codec interface.
func (c *Codec) Name() string { return "gzip" }

// NewReader implements the compress.Codec interface.
func (c *Codec) NewReader(r io.Reader) io.ReadCloser {
	var err error
	z, _ := readerPool.Get().(*gzip.Reader)
	if z != nil {
		err = z.Reset(r)
	} else {
		z, err = gzip.NewReader(r)
	}
	if err != nil {
		if z != nil {
			readerPool.Put(z)
		}
		return &errorReader{err: err}
	}
	return &reader{Reader: z}
}

// NewWriter implements the compress.Codec interface.
func (c *Codec) NewWriter(w io.Writer) io.WriteCloser {
	x := c.writerPool.Get()
	z, _ := x.(*gzip.Writer)
	if z == nil {
		x, err := gzip.NewWriterLevel(w, c.level())
		if err != nil {
			return &errorWriter{err: err}
		}
		z = x
	} else {
		z.Reset(w)
	}
	return &writer{codec: c, Writer: z}
}

func (c *Codec) level() int {
	if c.Level != 0 {
		return c.Level
	}
	return gzip.DefaultCompression
}

type reader struct{ *gzip.Reader }

func (r *reader) Close() (err error) {
	if z := r.Reader; z != nil {
		r.Reader = nil
		err = z.Close()
		// Pass it an empty reader, which is a zero-size value implementing the
		// flate.Reader interface to avoid the construction of a bufio.Reader in
		// the call to Reset.
		//
		// Note: we could also not reset the reader at all, but that would cause
		// the underlying reader to be retained until the gzip.Reader is freed,
		// which may not be desirable.
		z.Reset(emptyReader{})
		readerPool.Put(z)
	}
	return
}

type writer struct {
	codec *Codec
	*gzip.Writer
}

func (w *writer) Close() (err error) {
	if z := w.Writer; z != nil {
		w.Writer = nil
		err = z.Close()
		z.Reset(nil)
		w.codec.writerPool.Put(z)
	}
	return
}

type emptyReader struct{}

func (emptyReader) ReadByte() (byte, error) { return 0, io.EOF }

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

type errorReader struct{ err error }

func (r *errorReader) Close() error { return r.err }

func (r *errorReader) Read([]byte) (int, error) { return 0, r.err }

type errorWriter struct{ err error }

func (w *errorWriter) Close() error { return w.err }

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }
