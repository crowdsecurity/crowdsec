package snappy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/klauspost/compress/snappy"
)

const defaultBufferSize = 32 * 1024

// An implementation of io.Reader which consumes a stream of xerial-framed
// snappy-encoeded data. The framing is optional, if no framing is detected
// the reader will simply forward the bytes from its underlying stream.
type xerialReader struct {
	reader io.Reader
	header [16]byte
	input  []byte
	output []byte
	offset int64
	nbytes int64
	decode func([]byte, []byte) ([]byte, error)
}

func (x *xerialReader) Reset(r io.Reader) {
	x.reader = r
	x.input = x.input[:0]
	x.output = x.output[:0]
	x.header = [16]byte{}
	x.offset = 0
	x.nbytes = 0
}

func (x *xerialReader) Read(b []byte) (int, error) {
	for {
		if x.offset < int64(len(x.output)) {
			n := copy(b, x.output[x.offset:])
			x.offset += int64(n)
			return n, nil
		}

		n, err := x.readChunk(b)
		if err != nil {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
	}
}

func (x *xerialReader) WriteTo(w io.Writer) (int64, error) {
	wn := int64(0)

	for {
		for x.offset < int64(len(x.output)) {
			n, err := w.Write(x.output[x.offset:])
			wn += int64(n)
			x.offset += int64(n)
			if err != nil {
				return wn, err
			}
		}

		if _, err := x.readChunk(nil); err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return wn, err
		}
	}
}

func (x *xerialReader) readChunk(dst []byte) (int, error) {
	x.output = x.output[:0]
	x.offset = 0
	prefix := 0

	if x.nbytes == 0 {
		n, err := x.readFull(x.header[:])
		if err != nil && n == 0 {
			return 0, err
		}
		prefix = n
	}

	if isXerialHeader(x.header[:]) {
		if cap(x.input) < 4 {
			x.input = make([]byte, 4, defaultBufferSize)
		} else {
			x.input = x.input[:4]
		}

		_, err := x.readFull(x.input)
		if err != nil {
			return 0, err
		}

		frame := int(binary.BigEndian.Uint32(x.input))
		if cap(x.input) < frame {
			x.input = make([]byte, frame, align(frame, defaultBufferSize))
		} else {
			x.input = x.input[:frame]
		}

		if _, err := x.readFull(x.input); err != nil {
			return 0, err
		}
	} else {
		if cap(x.input) == 0 {
			x.input = make([]byte, 0, defaultBufferSize)
		} else {
			x.input = x.input[:0]
		}

		if prefix > 0 {
			x.input = append(x.input, x.header[:prefix]...)
		}

		for {
			if len(x.input) == cap(x.input) {
				b := make([]byte, len(x.input), 2*cap(x.input))
				copy(b, x.input)
				x.input = b
			}

			n, err := x.read(x.input[len(x.input):cap(x.input)])
			x.input = x.input[:len(x.input)+n]
			if err != nil {
				if errors.Is(err, io.EOF) && len(x.input) > 0 {
					break
				}
				return 0, err
			}
		}
	}

	var n int
	var err error

	if x.decode == nil {
		x.output, x.input, err = x.input, x.output, nil
	} else if n, err = snappy.DecodedLen(x.input); n <= len(dst) && err == nil {
		// If the output buffer is large enough to hold the decode value,
		// write it there directly instead of using the intermediary output
		// buffer.
		_, err = x.decode(dst, x.input)
	} else {
		var b []byte
		n = 0
		b, err = x.decode(x.output[:cap(x.output)], x.input)
		if err == nil {
			x.output = b
		}
	}

	return n, err
}

func (x *xerialReader) read(b []byte) (int, error) {
	n, err := x.reader.Read(b)
	x.nbytes += int64(n)
	return n, err
}

func (x *xerialReader) readFull(b []byte) (int, error) {
	n, err := io.ReadFull(x.reader, b)
	x.nbytes += int64(n)
	return n, err
}

// An implementation of a xerial-framed snappy-encoded output stream.
// Each Write made to the writer is framed with a xerial header.
type xerialWriter struct {
	writer io.Writer
	header [16]byte
	input  []byte
	output []byte
	nbytes int64
	framed bool
	encode func([]byte, []byte) []byte
}

func (x *xerialWriter) Reset(w io.Writer) {
	x.writer = w
	x.input = x.input[:0]
	x.output = x.output[:0]
	x.nbytes = 0
}

func (x *xerialWriter) ReadFrom(r io.Reader) (int64, error) {
	wn := int64(0)

	if cap(x.input) == 0 {
		x.input = make([]byte, 0, defaultBufferSize)
	}

	for {
		if x.full() {
			x.grow()
		}

		n, err := r.Read(x.input[len(x.input):cap(x.input)])
		wn += int64(n)
		x.input = x.input[:len(x.input)+n]

		if x.fullEnough() {
			if err := x.Flush(); err != nil {
				return wn, err
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			return wn, err
		}
	}
}

func (x *xerialWriter) Write(b []byte) (int, error) {
	wn := 0

	if cap(x.input) == 0 {
		x.input = make([]byte, 0, defaultBufferSize)
	}

	for len(b) > 0 {
		if x.full() {
			x.grow()
		}

		n := copy(x.input[len(x.input):cap(x.input)], b)
		b = b[n:]
		wn += n
		x.input = x.input[:len(x.input)+n]

		if x.fullEnough() {
			if err := x.Flush(); err != nil {
				return wn, err
			}
		}
	}

	return wn, nil
}

func (x *xerialWriter) Flush() error {
	if len(x.input) == 0 {
		return nil
	}

	var b []byte
	if x.encode == nil {
		b = x.input
	} else {
		x.output = x.encode(x.output[:cap(x.output)], x.input)
		b = x.output
	}

	x.input = x.input[:0]
	x.output = x.output[:0]

	if x.framed && x.nbytes == 0 {
		writeXerialHeader(x.header[:])
		_, err := x.write(x.header[:])
		if err != nil {
			return err
		}
	}

	if x.framed {
		writeXerialFrame(x.header[:4], len(b))
		_, err := x.write(x.header[:4])
		if err != nil {
			return err
		}
	}

	_, err := x.write(b)
	return err
}

func (x *xerialWriter) write(b []byte) (int, error) {
	n, err := x.writer.Write(b)
	x.nbytes += int64(n)
	return n, err
}

func (x *xerialWriter) full() bool {
	return len(x.input) == cap(x.input)
}

func (x *xerialWriter) fullEnough() bool {
	return x.framed && (cap(x.input)-len(x.input)) < 1024
}

func (x *xerialWriter) grow() {
	tmp := make([]byte, len(x.input), 2*cap(x.input))
	copy(tmp, x.input)
	x.input = tmp
}

func align(n, a int) int {
	if (n % a) == 0 {
		return n
	}
	return ((n / a) + 1) * a
}

var (
	xerialHeader      = [...]byte{130, 83, 78, 65, 80, 80, 89, 0}
	xerialVersionInfo = [...]byte{0, 0, 0, 1, 0, 0, 0, 1}
)

func isXerialHeader(src []byte) bool {
	return len(src) >= 16 && bytes.Equal(src[:8], xerialHeader[:])
}

func writeXerialHeader(b []byte) {
	copy(b[:8], xerialHeader[:])
	copy(b[8:], xerialVersionInfo[:])
}

func writeXerialFrame(b []byte, n int) {
	binary.BigEndian.PutUint32(b, uint32(n))
}
