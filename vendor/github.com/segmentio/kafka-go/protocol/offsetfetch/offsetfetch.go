package offsetfetch

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	GroupID string         `kafka:"min=v0,max=v5"`
	Topics  []RequestTopic `kafka:"min=v0,max=v5"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.OffsetFetch }

func (r *Request) Group() string { return r.GroupID }

type RequestTopic struct {
	Name             string  `kafka:"min=v0,max=v5"`
	PartitionIndexes []int32 `kafka:"min=v0,max=v5"`
}

var (
	_ protocol.GroupMessage = (*Request)(nil)
)

type Response struct {
	ThrottleTimeMs int32           `kafka:"min=v3,max=v5"`
	Topics         []ResponseTopic `kafka:"min=v0,max=v5"`
	ErrorCode      int16           `kafka:"min=v2,max=v5"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.OffsetFetch }

type ResponseTopic struct {
	Name       string              `kafka:"min=v0,max=v5"`
	Partitions []ResponsePartition `kafka:"min=v0,max=v5"`
}

type ResponsePartition struct {
	PartitionIndex      int32  `kafka:"min=v0,max=v5"`
	CommittedOffset     int64  `kafka:"min=v0,max=v5"`
	ComittedLeaderEpoch int32  `kafka:"min=v5,max=v5"`
	Metadata            string `kafka:"min=v0,max=v5,nullable"`
	ErrorCode           int16  `kafka:"min=v0,max=v5"`
}
