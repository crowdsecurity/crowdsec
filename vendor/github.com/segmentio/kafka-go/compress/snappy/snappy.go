package snappy

import (
	"io"
	"sync"

	"github.com/klauspost/compress/snappy"
)

// Framing is an enumeration type used to enable or disable xerial framing of
// snappy messages.
type Framing int

const (
	Framed Framing = iota
	Unframed
)

var (
	readerPool sync.Pool
	writerPool sync.Pool
)

// Codec is the implementation of a compress.Codec which supports creating
// readers and writers for kafka messages compressed with snappy.
type Codec struct {
	// An optional framing to apply to snappy compression.
	//
	// Default to Framed.
	Framing Framing
}

// Code implements the compress.Codec interface.
func (c *Codec) Code() int8 { return 2 }

// Name implements the compress.Codec interface.
func (c *Codec) Name() string { return "snappy" }

// NewReader implements the compress.Codec interface.
func (c *Codec) NewReader(r io.Reader) io.ReadCloser {
	x, _ := readerPool.Get().(*xerialReader)
	if x != nil {
		x.Reset(r)
	} else {
		x = &xerialReader{
			reader: r,
			decode: snappy.Decode,
		}
	}
	return &reader{xerialReader: x}
}

// NewWriter implements the compress.Codec interface.
func (c *Codec) NewWriter(w io.Writer) io.WriteCloser {
	x, _ := writerPool.Get().(*xerialWriter)
	if x != nil {
		x.Reset(w)
	} else {
		x = &xerialWriter{
			writer: w,
			encode: snappy.Encode,
		}
	}
	x.framed = c.Framing == Framed
	return &writer{xerialWriter: x}
}

type reader struct{ *xerialReader }

func (r *reader) Close() (err error) {
	if x := r.xerialReader; x != nil {
		r.xerialReader = nil
		x.Reset(nil)
		readerPool.Put(x)
	}
	return
}

type writer struct{ *xerialWriter }

func (w *writer) Close() (err error) {
	if x := w.xerialWriter; x != nil {
		w.xerialWriter = nil
		err = x.Flush()
		x.Reset(nil)
		writerPool.Put(x)
	}
	return
}
