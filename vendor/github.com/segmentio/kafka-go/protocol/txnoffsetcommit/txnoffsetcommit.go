package txnoffsetcommit

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	TransactionalID string         `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	GroupID         string         `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	ProducerID      int64          `kafka:"min=v0,max=v3"`
	ProducerEpoch   int16          `kafka:"min=v0,max=v3"`
	GenerationID    int32          `kafka:"min=v3,max=v3"`
	MemberID        string         `kafka:"min=v3,max=v3,compact"`
	GroupInstanceID string         `kafka:"min=v3,max=v3,compact,nullable"`
	Topics          []RequestTopic `kafka:"min=v0,max=v3"`
}

type RequestTopic struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Name       string             `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	Partitions []RequestPartition `kafka:"min=v0,max=v3"`
}

type RequestPartition struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Partition            int32  `kafka:"min=v0,max=v3"`
	CommittedOffset      int64  `kafka:"min=v0,max=v3"`
	CommittedLeaderEpoch int32  `kafka:"min=v2,max=v3"`
	CommittedMetadata    string `kafka:"min=v0,max=v2|min=v3,max=v3,nullable,compact"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.TxnOffsetCommit }

func (r *Request) Group() string { return r.GroupID }

var _ protocol.GroupMessage = (*Request)(nil)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	ThrottleTimeMs int32           `kafka:"min=v0,max=v3"`
	Topics         []ResponseTopic `kafka:"min=v0,max=v3"`
}

type ResponseTopic struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Name       string              `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	Partitions []ResponsePartition `kafka:"min=v0,max=v3"`
}

type ResponsePartition struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Partition int32 `kafka:"min=v0,max=v3"`
	ErrorCode int16 `kafka:"min=v0,max=v3"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.TxnOffsetCommit }
