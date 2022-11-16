package offsetcommit

import "github.com/segmentio/kafka-go/protocol"

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	GroupID         string         `kafka:"min=v0,max=v7"`
	GenerationID    int32          `kafka:"min=v1,max=v7"`
	MemberID        string         `kafka:"min=v1,max=v7"`
	RetentionTimeMs int64          `kafka:"min=v2,max=v4"`
	GroupInstanceID string         `kafka:"min=v7,max=v7,nullable"`
	Topics          []RequestTopic `kafka:"min=v0,max=v7"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.OffsetCommit }

func (r *Request) Group() string { return r.GroupID }

type RequestTopic struct {
	Name       string             `kafka:"min=v0,max=v7"`
	Partitions []RequestPartition `kafka:"min=v0,max=v7"`
}

type RequestPartition struct {
	PartitionIndex       int32  `kafka:"min=v0,max=v7"`
	CommittedOffset      int64  `kafka:"min=v0,max=v7"`
	CommitTimestamp      int64  `kafka:"min=v1,max=v1"`
	CommittedLeaderEpoch int32  `kafka:"min=v5,max=v7"`
	CommittedMetadata    string `kafka:"min=v0,max=v7,nullable"`
}

var (
	_ protocol.GroupMessage = (*Request)(nil)
)

type Response struct {
	ThrottleTimeMs int32           `kafka:"min=v3,max=v7"`
	Topics         []ResponseTopic `kafka:"min=v0,max=v7"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.OffsetCommit }

type ResponseTopic struct {
	Name       string              `kafka:"min=v0,max=v7"`
	Partitions []ResponsePartition `kafka:"min=v0,max=v7"`
}

type ResponsePartition struct {
	PartitionIndex int32 `kafka:"min=v0,max=v7"`
	ErrorCode      int16 `kafka:"min=v0,max=v7"`
}
