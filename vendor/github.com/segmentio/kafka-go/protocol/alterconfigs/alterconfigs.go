package alterconfigs

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

// Detailed API definition: https://kafka.apache.org/protocol#The_Messages_AlterConfigs
type Request struct {
	Resources    []RequestResources `kafka:"min=v0,max=v1"`
	ValidateOnly bool               `kafka:"min=v0,max=v1"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.AlterConfigs }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	return cluster.Brokers[cluster.Controller], nil
}

type RequestResources struct {
	ResourceType int8            `kafka:"min=v0,max=v1"`
	ResourceName string          `kafka:"min=v0,max=v1"`
	Configs      []RequestConfig `kafka:"min=v0,max=v1"`
}

type RequestConfig struct {
	Name  string `kafka:"min=v0,max=v1"`
	Value string `kafka:"min=v0,max=v1,nullable"`
}

type Response struct {
	ThrottleTimeMs int32               `kafka:"min=v0,max=v1"`
	Responses      []ResponseResponses `kafka:"min=v0,max=v1"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.AlterConfigs }

type ResponseResponses struct {
	ErrorCode    int16  `kafka:"min=v0,max=v1"`
	ErrorMessage string `kafka:"min=v0,max=v1,nullable"`
	ResourceType int8   `kafka:"min=v0,max=v1"`
	ResourceName string `kafka:"min=v0,max=v1"`
}

var (
	_ protocol.BrokerMessage = (*Request)(nil)
)
