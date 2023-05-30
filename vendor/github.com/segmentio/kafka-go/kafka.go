package kafka

import "github.com/segmentio/kafka-go/protocol"

// Broker represents a kafka broker in a kafka cluster.
type Broker struct {
	Host string
	Port int
	ID   int
	Rack string
}

// Topic represents a topic in a kafka cluster.
type Topic struct {
	// Name of the topic.
	Name string

	// True if the topic is internal.
	Internal bool

	// The list of partition currently available on this topic.
	Partitions []Partition

	// An error that may have occurred while attempting to read the topic
	// metadata.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error
}

// Partition carries the metadata associated with a kafka partition.
type Partition struct {
	// Name of the topic that the partition belongs to, and its index in the
	// topic.
	Topic string
	ID    int

	// Leader, replicas, and ISR for the partition.
	Leader   Broker
	Replicas []Broker
	Isr      []Broker

	// An error that may have occurred while attempting to read the partition
	// metadata.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error
}

// Marshal encodes v into a binary representation of the value in the kafka data
// format.
//
// If v is a, or contains struct types, the kafka struct fields are interpreted
// and may contain one of these values:
//
//	nullable  valid on bytes and strings, encodes as a nullable value
//	compact   valid on strings, encodes as a compact string
//
// The kafka struct tags should not contain min and max versions. If you need to
// encode types based on specific versions of kafka APIs, use the Version type
// instead.
func Marshal(v interface{}) ([]byte, error) {
	return protocol.Marshal(-1, v)
}

// Unmarshal decodes a binary representation from b into v.
//
// See Marshal for details.
func Unmarshal(b []byte, v interface{}) error {
	return protocol.Unmarshal(b, -1, v)
}

// Version represents a version number for kafka APIs.
type Version int16

// Marshal is like the top-level Marshal function, but will only encode struct
// fields for which n falls within the min and max versions specified on the
// struct tag.
func (n Version) Marshal(v interface{}) ([]byte, error) {
	return protocol.Marshal(int16(n), v)
}

// Unmarshal is like the top-level Unmarshal function, but will only decode
// struct fields for which n falls within the min and max versions specified on
// the struct tag.
func (n Version) Unmarshal(b []byte, v interface{}) error {
	return protocol.Unmarshal(b, int16(n), v)
}
