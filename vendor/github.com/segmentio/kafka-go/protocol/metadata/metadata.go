package metadata

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	TopicNames                         []string `kafka:"min=v0,max=v8,nullable"`
	AllowAutoTopicCreation             bool     `kafka:"min=v4,max=v8"`
	IncludeClusterAuthorizedOperations bool     `kafka:"min=v8,max=v8"`
	IncludeTopicAuthorizedOperations   bool     `kafka:"min=v8,max=v8"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.Metadata }

type Response struct {
	ThrottleTimeMs              int32            `kafka:"min=v3,max=v8"`
	Brokers                     []ResponseBroker `kafka:"min=v0,max=v8"`
	ClusterID                   string           `kafka:"min=v2,max=v8,nullable"`
	ControllerID                int32            `kafka:"min=v1,max=v8"`
	Topics                      []ResponseTopic  `kafka:"min=v0,max=v8"`
	ClusterAuthorizedOperations int32            `kafka:"min=v8,max=v8"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.Metadata }

type ResponseBroker struct {
	NodeID int32  `kafka:"min=v0,max=v8"`
	Host   string `kafka:"min=v0,max=v8"`
	Port   int32  `kafka:"min=v0,max=v8"`
	Rack   string `kafka:"min=v1,max=v8,nullable"`
}

type ResponseTopic struct {
	ErrorCode                 int16               `kafka:"min=v0,max=v8"`
	Name                      string              `kafka:"min=v0,max=v8"`
	IsInternal                bool                `kafka:"min=v1,max=v8"`
	Partitions                []ResponsePartition `kafka:"min=v0,max=v8"`
	TopicAuthorizedOperations int32               `kafka:"min=v8,max=v8"`
}

type ResponsePartition struct {
	ErrorCode       int16   `kafka:"min=v0,max=v8"`
	PartitionIndex  int32   `kafka:"min=v0,max=v8"`
	LeaderID        int32   `kafka:"min=v0,max=v8"`
	LeaderEpoch     int32   `kafka:"min=v7,max=v8"`
	ReplicaNodes    []int32 `kafka:"min=v0,max=v8"`
	IsrNodes        []int32 `kafka:"min=v0,max=v8"`
	OfflineReplicas []int32 `kafka:"min=v5,max=v8"`
}
