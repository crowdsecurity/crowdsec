package createpartitions

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_CreatePartitions.
// TODO: Support version 2.
type Request struct {
	Topics       []RequestTopic `kafka:"min=v0,max=v1"`
	TimeoutMs    int32          `kafka:"min=v0,max=v1"`
	ValidateOnly bool           `kafka:"min=v0,max=v1"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.CreatePartitions }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	return cluster.Brokers[cluster.Controller], nil
}

type RequestTopic struct {
	Name        string              `kafka:"min=v0,max=v1"`
	Count       int32               `kafka:"min=v0,max=v1"`
	Assignments []RequestAssignment `kafka:"min=v0,max=v1,nullable"`
}

type RequestAssignment struct {
	BrokerIDs []int32 `kafka:"min=v0,max=v1"`
}

type Response struct {
	ThrottleTimeMs int32            `kafka:"min=v0,max=v1"`
	Results        []ResponseResult `kafka:"min=v0,max=v1"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.CreatePartitions }

type ResponseResult struct {
	Name         string `kafka:"min=v0,max=v1"`
	ErrorCode    int16  `kafka:"min=v0,max=v1"`
	ErrorMessage string `kafka:"min=v0,max=v1,nullable"`
}

var _ protocol.BrokerMessage = (*Request)(nil)
