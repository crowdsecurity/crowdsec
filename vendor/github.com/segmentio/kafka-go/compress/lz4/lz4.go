package lz4

import (
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

var (
	readerPool sync.Pool
	writerPool sync.Pool
)

// Codec is the implementation of a compress.Codec which supports creating
// readers and writers for kafka messages compressed with lz4.
type Codec struct{}

// Code implements the compress.Codec interface.
func (c *Codec) Code() int8 { return 3 }

// Name implements the compress.Codec interface.
func (c *Codec) Name() string { return "lz4" }

// NewReader implements the compress.Codec interface.
func (c *Codec) NewReader(r io.Reader) io.ReadCloser {
	z, _ := readerPool.Get().(*lz4.Reader)
	if z != nil {
		z.Reset(r)
	} else {
		z = lz4.NewReader(r)
	}
	return &reader{Reader: z}
}

// NewWriter implements the compress.Codec interface.
func (c *Codec) NewWriter(w io.Writer) io.WriteCloser {
	z, _ := writerPool.Get().(*lz4.Writer)
	if z != nil {
		z.Reset(w)
	} else {
		z = lz4.NewWriter(w)
	}
	return &writer{Writer: z}
}

type reader struct{ *lz4.Reader }

func (r *reader) Close() (err error) {
	if z := r.Reader; z != nil {
		r.Reader = nil
		z.Reset(nil)
		readerPool.Put(z)
	}
	return
}

type writer struct{ *lz4.Writer }

func (w *writer) Close() (err error) {
	if z := w.Writer; z != nil {
		w.Writer = nil
		err = z.Close()
		z.Reset(nil)
		writerPool.Put(z)
	}
	return
}
