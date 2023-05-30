package joingroup

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v6,max=v7,tag"`

	GroupID            string            `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	SessionTimeoutMS   int32             `kafka:"min=v0,max=v7"`
	RebalanceTimeoutMS int32             `kafka:"min=v1,max=v7"`
	MemberID           string            `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	GroupInstanceID    string            `kafka:"min=v5,max=v5,nullable|min=v6,max=v7,compact,nullable"`
	ProtocolType       string            `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	Protocols          []RequestProtocol `kafka:"min=v0,max=v7"`
}

type RequestProtocol struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v6,max=v7,tag"`

	Name     string `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	Metadata []byte `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
}

func (r *Request) ApiKey() protocol.ApiKey {
	return protocol.JoinGroup
}

func (r *Request) Group() string { return r.GroupID }

var _ protocol.GroupMessage = (*Request)(nil)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v6,max=v7,tag"`

	ThrottleTimeMS int32            `kafka:"min=v2,max=v7"`
	ErrorCode      int16            `kafka:"min=v0,max=v7"`
	GenerationID   int32            `kafka:"min=v0,max=v7"`
	ProtocolType   string           `kafka:"min=v7,max=v7,compact,nullable"`
	ProtocolName   string           `kafka:"min=v0,max=v5|min=v6,max=v6,compact|min=v7,max=v7,compact,nullable"`
	LeaderID       string           `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	MemberID       string           `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	Members        []ResponseMember `kafka:"min=v0,max=v7"`
}

type ResponseMember struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v6,max=v7,tag"`

	MemberID        string `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
	GroupInstanceID string `kafka:"min=v5,max=v5,nullable|min=v6,max=v7,nullable,compact"`
	Metadata        []byte `kafka:"min=v0,max=v5|min=v6,max=v7,compact"`
}

type ResponseMemberMetadata struct{}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.JoinGroup }
