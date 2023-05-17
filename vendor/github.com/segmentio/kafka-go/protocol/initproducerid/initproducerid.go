package initproducerid

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v2,max=v4,tag"`

	TransactionalID      string `kafka:"min=v0,max=v4,nullable"`
	TransactionTimeoutMs int32  `kafka:"min=v0,max=v4"`
	ProducerID           int64  `kafka:"min=v3,max=v4"`
	ProducerEpoch        int16  `kafka:"min=v3,max=v4"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.InitProducerId }

func (r *Request) Transaction() string { return r.TransactionalID }

var _ protocol.TransactionalMessage = (*Request)(nil)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v2,max=v4,tag"`

	ThrottleTimeMs int32 `kafka:"min=v0,max=v4"`
	ErrorCode      int16 `kafka:"min=v0,max=v4"`
	ProducerID     int64 `kafka:"min=v0,max=v4"`
	ProducerEpoch  int16 `kafka:"min=v0,max=v4"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.InitProducerId }
