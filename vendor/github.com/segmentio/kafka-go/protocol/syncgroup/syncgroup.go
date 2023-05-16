package syncgroup

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v5,tag"`

	GroupID         string              `kafka:"min=v0,max=v3|min=v4,max=v5,compact"`
	GenerationID    int32               `kafka:"min=v0,max=v5|min=v4,max=v5,compact"`
	MemberID        string              `kafka:"min=v0,max=v3|min=v4,max=v5,compact"`
	GroupInstanceID string              `kafka:"min=v3,max=v3,nullable|min=v4,max=v5,nullable,compact"`
	ProtocolType    string              `kafka:"min=v5,max=v5"`
	ProtocolName    string              `kafka:"min=v5,max=v5"`
	Assignments     []RequestAssignment `kafka:"min=v0,max=v5"`
}

type RequestAssignment struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v5,tag"`

	MemberID   string `kafka:"min=v0,max=v3|min=v4,max=v5,compact"`
	Assignment []byte `kafka:"min=v0,max=v3|min=v4,max=v5,compact"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.SyncGroup }

func (r *Request) Group() string { return r.GroupID }

var _ protocol.GroupMessage = (*Request)(nil)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v5,tag"`

	ThrottleTimeMS int32  `kafka:"min=v1,max=v5"`
	ErrorCode      int16  `kafka:"min=v0,max=v5"`
	ProtocolType   string `kafka:"min=v5,max=v5"`
	ProtocolName   string `kafka:"min=v5,max=v5"`
	Assignments    []byte `kafka:"min=v0,max=v3|min=v4,max=v5,compact"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.SyncGroup }
