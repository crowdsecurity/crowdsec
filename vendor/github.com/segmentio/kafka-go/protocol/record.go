package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/segmentio/kafka-go/compress"
)

// Attributes is a bitset representing special attributes set on records.
type Attributes int16

const (
	Gzip          Attributes = Attributes(compress.Gzip)   // 1
	Snappy        Attributes = Attributes(compress.Snappy) // 2
	Lz4           Attributes = Attributes(compress.Lz4)    // 3
	Zstd          Attributes = Attributes(compress.Zstd)   // 4
	Transactional Attributes = 1 << 4
	Control       Attributes = 1 << 5
)

func (a Attributes) Compression() compress.Compression {
	return compress.Compression(a & 7)
}

func (a Attributes) Transactional() bool {
	return (a & Transactional) != 0
}

func (a Attributes) Control() bool {
	return (a & Control) != 0
}

func (a Attributes) String() string {
	s := a.Compression().String()
	if a.Transactional() {
		s += "+transactional"
	}
	if a.Control() {
		s += "+control"
	}
	return s
}

// Header represents a single entry in a list of record headers.
type Header struct {
	Key   string
	Value []byte
}

// Record is an interface representing a single kafka record.
//
// Record values are not safe to use concurrently from multiple goroutines.
type Record struct {
	// The offset at which the record exists in a topic partition. This value
	// is ignored in produce requests.
	Offset int64

	// Returns the time of the record. This value may be omitted in produce
	// requests to let kafka set the time when it saves the record.
	Time time.Time

	// Returns a byte sequence containing the key of this record. The returned
	// sequence may be nil to indicate that the record has no key. If the record
	// is part of a RecordSet, the content of the key must remain valid at least
	// until the record set is closed (or until the key is closed).
	Key Bytes

	// Returns a byte sequence containing the value of this record. The returned
	// sequence may be nil to indicate that the record has no value. If the
	// record is part of a RecordSet, the content of the value must remain valid
	// at least until the record set is closed (or until the value is closed).
	Value Bytes

	// Returns the list of headers associated with this record. The returned
	// slice may be reused across calls, the program should use it as an
	// immutable value.
	Headers []Header
}

// RecordSet represents a sequence of records in Produce requests and Fetch
// responses. All v0, v1, and v2 formats are supported.
type RecordSet struct {
	// The message version that this record set will be represented as, valid
	// values are 1, or 2.
	//
	// When reading, this is the value of the highest version used in the
	// batches that compose the record set.
	//
	// When writing, this value dictates the format that the records will be
	// encoded in.
	Version int8

	// Attributes set on the record set.
	//
	// When reading, the attributes are the combination of all attributes in
	// the batches that compose the record set.
	//
	// When writing, the attributes apply to the whole sequence of records in
	// the set.
	Attributes Attributes

	// A reader exposing the sequence of records.
	//
	// When reading a RecordSet from an io.Reader, the Records field will be a
	// *RecordStream. If the program needs to access the details of each batch
	// that compose the stream, it may use type assertions to access the
	// underlying types of each batch.
	Records RecordReader
}

// bufferedReader is an interface implemented by types like bufio.Reader, which
// we use to optimize prefix reads by accessing the internal buffer directly
// through calls to Peek.
type bufferedReader interface {
	Discard(int) (int, error)
	Peek(int) ([]byte, error)
}

// bytesBuffer is an interface implemented by types like bytes.Buffer, which we
// use to optimize prefix reads by accessing the internal buffer directly
// through calls to Bytes.
type bytesBuffer interface {
	Bytes() []byte
}

// magicByteOffset is the position of the magic byte in all versions of record
// sets in the kafka protocol.
const magicByteOffset = 16

// ReadFrom reads the representation of a record set from r into rs, returning
// the number of bytes consumed from r, and an non-nil error if the record set
// could not be read.
func (rs *RecordSet) ReadFrom(r io.Reader) (int64, error) {
	d, _ := r.(*decoder)
	if d == nil {
		d = &decoder{
			reader: r,
			remain: 4,
		}
	}

	*rs = RecordSet{}
	limit := d.remain
	size := d.readInt32()

	if d.err != nil {
		return int64(limit - d.remain), d.err
	}

	if size <= 0 {
		return 4, nil
	}

	stream := &RecordStream{
		Records: make([]RecordReader, 0, 4),
	}

	var err error
	d.remain = int(size)

	for d.remain > 0 && err == nil {
		var version byte

		if d.remain < (magicByteOffset + 1) {
			if len(stream.Records) != 0 {
				break
			}
			return 4, fmt.Errorf("impossible record set shorter than %d bytes", magicByteOffset+1)
		}

		switch r := d.reader.(type) {
		case bufferedReader:
			b, err := r.Peek(magicByteOffset + 1)
			if err != nil {
				n, _ := r.Discard(len(b))
				return 4 + int64(n), dontExpectEOF(err)
			}
			version = b[magicByteOffset]
		case bytesBuffer:
			version = r.Bytes()[magicByteOffset]
		default:
			b := make([]byte, magicByteOffset+1)
			if n, err := io.ReadFull(d.reader, b); err != nil {
				return 4 + int64(n), dontExpectEOF(err)
			}
			version = b[magicByteOffset]
			// Reconstruct the prefix that we had to read to determine the version
			// of the record set from the magic byte.
			//
			// Technically this may recurisvely stack readers when consuming all
			// items of the batch, which could hurt performance. In practice this
			// path should not be taken tho, since the decoder would read from a
			// *bufio.Reader which implements the bufferedReader interface.
			d.reader = io.MultiReader(bytes.NewReader(b), d.reader)
		}

		var tmp RecordSet
		switch version {
		case 0, 1:
			err = tmp.readFromVersion1(d)
		case 2:
			err = tmp.readFromVersion2(d)
		default:
			err = fmt.Errorf("unsupported message version %d for message of size %d", version, size)
		}

		if tmp.Version > rs.Version {
			rs.Version = tmp.Version
		}

		rs.Attributes |= tmp.Attributes

		if tmp.Records != nil {
			stream.Records = append(stream.Records, tmp.Records)
		}
	}

	if len(stream.Records) != 0 {
		rs.Records = stream
		// Ignore errors if we've successfully read records, so the
		// program can keep making progress.
		err = nil
	}

	d.discardAll()
	rn := 4 + (int(size) - d.remain)
	d.remain = limit - rn
	return int64(rn), err
}

// WriteTo writes the representation of rs into w. The value of rs.Version
// dictates which format that the record set will be represented as.
//
// The error will be ErrNoRecord if rs contained no records.
//
// Note: since this package is only compatible with kafka 0.10 and above, the
// method never produces messages in version 0. If rs.Version is zero, the
// method defaults to producing messages in version 1.
func (rs *RecordSet) WriteTo(w io.Writer) (int64, error) {
	if rs.Records == nil {
		return 0, ErrNoRecord
	}

	// This optimization avoids rendering the record set in an intermediary
	// buffer when the writer is already a pageBuffer, which is a common case
	// due to the way WriteRequest and WriteResponse are implemented.
	buffer, _ := w.(*pageBuffer)
	bufferOffset := int64(0)

	if buffer != nil {
		bufferOffset = buffer.Size()
	} else {
		buffer = newPageBuffer()
		defer buffer.unref()
	}

	size := packUint32(0)
	buffer.Write(size[:]) // size placeholder

	var err error
	switch rs.Version {
	case 0, 1:
		err = rs.writeToVersion1(buffer, bufferOffset+4)
	case 2:
		err = rs.writeToVersion2(buffer, bufferOffset+4)
	default:
		err = fmt.Errorf("unsupported record set version %d", rs.Version)
	}
	if err != nil {
		return 0, err
	}

	n := buffer.Size() - bufferOffset
	if n == 0 {
		size = packUint32(^uint32(0))
	} else {
		size = packUint32(uint32(n) - 4)
	}
	buffer.WriteAt(size[:], bufferOffset)

	// This condition indicates that the output writer received by `WriteTo` was
	// not a *pageBuffer, in which case we need to flush the buffered records
	// data into it.
	if buffer != w {
		return buffer.WriteTo(w)
	}

	return n, nil
}

func makeTime(t int64) time.Time {
	return time.Unix(t/1000, (t%1000)*int64(time.Millisecond))
}

func timestamp(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano() / int64(time.Millisecond)
}

func packUint32(u uint32) (b [4]byte) {
	binary.BigEndian.PutUint32(b[:], u)
	return
}

func packUint64(u uint64) (b [8]byte) {
	binary.BigEndian.PutUint64(b[:], u)
	return
}
