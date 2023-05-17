package kafka

import (
	"github.com/segmentio/kafka-go/protocol"
)

// Header is a key/value pair type representing headers set on records.
type Header = protocol.Header

// Bytes is an interface representing a sequence of bytes. This abstraction
// makes it possible for programs to inject data into produce requests without
// having to load in into an intermediary buffer, or read record keys and values
// from a fetch response directly from internal buffers.
//
// Bytes are not safe to use concurrently from multiple goroutines.
type Bytes = protocol.Bytes

// NewBytes constructs a Bytes value from a byte slice.
//
// If b is nil, nil is returned.
func NewBytes(b []byte) Bytes { return protocol.NewBytes(b) }

// ReadAll reads b into a byte slice.
func ReadAll(b Bytes) ([]byte, error) { return protocol.ReadAll(b) }

// Record is an interface representing a single kafka record.
//
// Record values are not safe to use concurrently from multiple goroutines.
type Record = protocol.Record

// RecordReader is an interface representing a sequence of records. Record sets
// are used in both produce and fetch requests to represent the sequence of
// records that are sent to or receive from kafka brokers.
//
// RecordReader values are not safe to use concurrently from multiple goroutines.
type RecordReader = protocol.RecordReader

// NewRecordReade reconstructs a RecordSet which exposes the sequence of records
// passed as arguments.
func NewRecordReader(records ...Record) RecordReader {
	return protocol.NewRecordReader(records...)
}
