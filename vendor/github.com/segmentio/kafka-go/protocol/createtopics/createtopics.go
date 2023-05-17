package createtopics

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	// We need at least one tagged field to indicate that v5+ uses "flexible"
	// messages.
	_ struct{} `kafka:"min=v5,max=v5,tag"`

	Topics       []RequestTopic `kafka:"min=v0,max=v5"`
	TimeoutMs    int32          `kafka:"min=v0,max=v5"`
	ValidateOnly bool           `kafka:"min=v1,max=v5"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.CreateTopics }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	return cluster.Brokers[cluster.Controller], nil
}

type RequestTopic struct {
	Name              string              `kafka:"min=v0,max=v5"`
	NumPartitions     int32               `kafka:"min=v0,max=v5"`
	ReplicationFactor int16               `kafka:"min=v0,max=v5"`
	Assignments       []RequestAssignment `kafka:"min=v0,max=v5"`
	Configs           []RequestConfig     `kafka:"min=v0,max=v5"`
}

type RequestAssignment struct {
	PartitionIndex int32   `kafka:"min=v0,max=v5"`
	BrokerIDs      []int32 `kafka:"min=v0,max=v5"`
}

type RequestConfig struct {
	Name  string `kafka:"min=v0,max=v5"`
	Value string `kafka:"min=v0,max=v5,nullable"`
}

type Response struct {
	// We need at least one tagged field to indicate that v5+ uses "flexible"
	// messages.
	_ struct{} `kafka:"min=v5,max=v5,tag"`

	ThrottleTimeMs int32           `kafka:"min=v2,max=v5"`
	Topics         []ResponseTopic `kafka:"min=v0,max=v5"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.CreateTopics }

type ResponseTopic struct {
	Name              string `kafka:"min=v0,max=v5"`
	ErrorCode         int16  `kafka:"min=v0,max=v5"`
	ErrorMessage      string `kafka:"min=v1,max=v5,nullable"`
	NumPartitions     int32  `kafka:"min=v5,max=v5"`
	ReplicationFactor int16  `kafka:"min=v5,max=v5"`

	Configs []ResponseTopicConfig `kafka:"min=v5,max=v5"`
}

type ResponseTopicConfig struct {
	Name         string `kafka:"min=v5,max=v5"`
	Value        string `kafka:"min=v5,max=v5,nullable"`
	ReadOnly     bool   `kafka:"min=v5,max=v5"`
	ConfigSource int8   `kafka:"min=v5,max=v5"`
	IsSensitive  bool   `kafka:"min=v5,max=v5"`
}

var (
	_ protocol.BrokerMessage = (*Request)(nil)
)
