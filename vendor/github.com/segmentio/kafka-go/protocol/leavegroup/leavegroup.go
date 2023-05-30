package leavegroup

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	GroupID  string          `kafka:"min=v0,max=v2|min=v3,max=v4,compact"`
	MemberID string          `kafka:"min=v0,max=v2"`
	Members  []RequestMember `kafka:"min=v3,max=v4"`
}

func (r *Request) Prepare(apiVersion int16) {
	if apiVersion < 3 {
		if len(r.Members) > 0 {
			r.MemberID = r.Members[0].MemberID
		}
	}
}

type RequestMember struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	MemberID        string `kafka:"min=v3,max=v3|min=v4,max=v4,compact"`
	GroupInstanceID string `kafka:"min=v3,max=v3,nullable|min=v4,max=v4,nullable,compact"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.LeaveGroup }

func (r *Request) Group() string { return r.GroupID }

var (
	_ protocol.GroupMessage    = (*Request)(nil)
	_ protocol.PreparedMessage = (*Request)(nil)
)

type Response struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	ErrorCode      int16            `kafka:"min=v0,max=v4"`
	ThrottleTimeMS int32            `kafka:"min=v1,max=v4"`
	Members        []ResponseMember `kafka:"min=v3,max=v4"`
}

type ResponseMember struct {
	// We need at least one tagged field to indicate that this is a "flexible" message
	// type.
	_ struct{} `kafka:"min=v4,max=v4,tag"`

	MemberID        string `kafka:"min=v3,max=v3|min=v4,max=v4,compact"`
	GroupInstanceID string `kafka:"min=v3,max=v3,nullable|min=v4,max=v4,nullable,compact"`
	ErrorCode       int16  `kafka:"min=v3,max=v4"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.LeaveGroup }
