package addpartitionstotxn

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	TransactionalID string         `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	ProducerID      int64          `kafka:"min=v0,max=v3"`
	ProducerEpoch   int16          `kafka:"min=v0,max=v3"`
	Topics          []RequestTopic `kafka:"min=v0,max=v3"`
}

type RequestTopic struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Name       string  `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	Partitions []int32 `kafka:"min=v0,max=v3"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.AddPartitionsToTxn }

func (r *Request) Transaction() string { return r.TransactionalID }

var _ protocol.TransactionalMessage = (*Request)(nil)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	ThrottleTimeMs int32            `kafka:"min=v0,max=v3"`
	Results        []ResponseResult `kafka:"min=v0,max=v3"`
}

type ResponseResult struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	Name    string              `kafka:"min=v0,max=v2|min=v3,max=v3,compact"`
	Results []ResponsePartition `kafka:"min=v0,max=v3"`
}

type ResponsePartition struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v3,max=v3,tag"`

	PartitionIndex int32 `kafka:"min=v0,max=v3"`
	ErrorCode      int16 `kafka:"min=v0,max=v3"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.AddPartitionsToTxn }
