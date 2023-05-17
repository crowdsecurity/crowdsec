package deletetopics

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	TopicNames []string `kafka:"min=v0,max=v3"`
	TimeoutMs  int32    `kafka:"min=v0,max=v3"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.DeleteTopics }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	return cluster.Brokers[cluster.Controller], nil
}

type Response struct {
	ThrottleTimeMs int32           `kafka:"min=v1,max=v3"`
	Responses      []ResponseTopic `kafka:"min=v0,max=v3"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.DeleteTopics }

type ResponseTopic struct {
	Name      string `kafka:"min=v0,max=v3"`
	ErrorCode int16  `kafka:"min=v0,max=v3"`
}

var (
	_ protocol.BrokerMessage = (*Request)(nil)
)
