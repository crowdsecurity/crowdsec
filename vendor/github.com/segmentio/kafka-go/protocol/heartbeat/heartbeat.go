package heartbeat

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_Heartbeat
type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	GroupID         string `kafka:"min=v0,max=v4"`
	GenerationID    int32  `kafka:"min=v0,max=v4"`
	MemberID        string `kafka:"min=v0,max=v4"`
	GroupInstanceID string `kafka:"min=v3,max=v4,nullable"`
}

func (r *Request) ApiKey() protocol.ApiKey {
	return protocol.Heartbeat
}

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	ErrorCode      int16 `kafka:"min=v0,max=v4"`
	ThrottleTimeMs int32 `kafka:"min=v1,max=v4"`
}

func (r *Response) ApiKey() protocol.ApiKey {
	return protocol.Heartbeat
}
