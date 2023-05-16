package findcoordinator

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	Key     string `kafka:"min=v0,max=v2"`
	KeyType int8   `kafka:"min=v1,max=v2"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.FindCoordinator }

type Response struct {
	ThrottleTimeMs int32  `kafka:"min=v1,max=v2"`
	ErrorCode      int16  `kafka:"min=v0,max=v2"`
	ErrorMessage   string `kafka:"min=v1,max=v2,nullable"`
	NodeID         int32  `kafka:"min=v0,max=v2"`
	Host           string `kafka:"min=v0,max=v2"`
	Port           int32  `kafka:"min=v0,max=v2"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.FindCoordinator }
