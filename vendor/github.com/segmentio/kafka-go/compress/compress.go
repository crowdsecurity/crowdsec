package compress

import (
	"encoding"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/segmentio/kafka-go/compress/gzip"
	"github.com/segmentio/kafka-go/compress/lz4"
	"github.com/segmentio/kafka-go/compress/snappy"
	"github.com/segmentio/kafka-go/compress/zstd"
)

// Compression represents the the compression applied to a record set.
type Compression int8

const (
	None   Compression = 0
	Gzip   Compression = 1
	Snappy Compression = 2
	Lz4    Compression = 3
	Zstd   Compression = 4
)

func (c Compression) Codec() Codec {
	if i := int(c); i >= 0 && i < len(Codecs) {
		return Codecs[i]
	}
	return nil
}

func (c Compression) String() string {
	if codec := c.Codec(); codec != nil {
		return codec.Name()
	}
	return "uncompressed"
}

func (c Compression) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

func (c *Compression) UnmarshalText(b []byte) error {
	switch string(b) {
	case "none", "uncompressed":
		*c = None
		return nil
	}

	for _, codec := range Codecs[None+1:] {
		if codec.Name() == string(b) {
			*c = Compression(codec.Code())
			return nil
		}
	}

	i, err := strconv.ParseInt(string(b), 10, 64)
	if err == nil && i >= 0 && i < int64(len(Codecs)) {
		*c = Compression(i)
		return nil
	}

	s := &strings.Builder{}
	s.WriteString("none, uncompressed")

	for i, codec := range Codecs[None+1:] {
		if i < (len(Codecs) - 1) {
			s.WriteString(", ")
		} else {
			s.WriteString(", or ")
		}
		s.WriteString(codec.Name())
	}

	return fmt.Errorf("compression format must be one of %s, not %q", s, b)
}

var (
	_ encoding.TextMarshaler   = Compression(0)
	_ encoding.TextUnmarshaler = (*Compression)(nil)
)

// Codec represents a compression codec to encode and decode the messages.
// See : https://cwiki.apache.org/confluence/display/KAFKA/Compression
//
// A Codec must be safe for concurrent access by multiple go routines.
type Codec interface {
	// Code returns the compression codec code
	Code() int8

	// Human-readable name for the codec.
	Name() string

	// Constructs a new reader which decompresses data from r.
	NewReader(r io.Reader) io.ReadCloser

	// Constructs a new writer which writes compressed data to w.
	NewWriter(w io.Writer) io.WriteCloser
}

var (
	// The global gzip codec installed on the Codecs table.
	GzipCodec gzip.Codec

	// The global snappy codec installed on the Codecs table.
	SnappyCodec snappy.Codec

	// The global lz4 codec installed on the Codecs table.
	Lz4Codec lz4.Codec

	// The global zstd codec installed on the Codecs table.
	ZstdCodec zstd.Codec

	// The global table of compression codecs supported by the kafka protocol.
	Codecs = [...]Codec{
		None:   nil,
		Gzip:   &GzipCodec,
		Snappy: &SnappyCodec,
		Lz4:    &Lz4Codec,
		Zstd:   &ZstdCodec,
	}
)
