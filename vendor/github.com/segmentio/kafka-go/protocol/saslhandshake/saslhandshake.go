package saslhandshake

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	Mechanism string `kafka:"min=v0,max=v1"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.SaslHandshake }

type Response struct {
	ErrorCode  int16    `kafka:"min=v0,max=v1"`
	Mechanisms []string `kafka:"min=v0,max=v1"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.SaslHandshake }
