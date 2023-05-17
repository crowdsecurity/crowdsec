package fetch

import (
	"fmt"

	"github.com/segmentio/kafka-go/protocol"
)

func init() {
	protocol.Register(&Request{}, &Response{})
}

type Request struct {
	ReplicaID       int32                   `kafka:"min=v0,max=v11"`
	MaxWaitTime     int32                   `kafka:"min=v0,max=v11"`
	MinBytes        int32                   `kafka:"min=v0,max=v11"`
	MaxBytes        int32                   `kafka:"min=v3,max=v11"`
	IsolationLevel  int8                    `kafka:"min=v4,max=v11"`
	SessionID       int32                   `kafka:"min=v7,max=v11"`
	SessionEpoch    int32                   `kafka:"min=v7,max=v11"`
	Topics          []RequestTopic          `kafka:"min=v0,max=v11"`
	ForgottenTopics []RequestForgottenTopic `kafka:"min=v7,max=v11"`
	RackID          string                  `kafka:"min=v11,max=v11"`
}

func (r *Request) ApiKey() protocol.ApiKey { return protocol.Fetch }

func (r *Request) Broker(cluster protocol.Cluster) (protocol.Broker, error) {
	broker := protocol.Broker{ID: -1}

	for i := range r.Topics {
		t := &r.Topics[i]

		topic, ok := cluster.Topics[t.Topic]
		if !ok {
			return broker, NewError(protocol.NewErrNoTopic(t.Topic))
		}

		for j := range t.Partitions {
			p := &t.Partitions[j]

			partition, ok := topic.Partitions[p.Partition]
			if !ok {
				return broker, NewError(protocol.NewErrNoPartition(t.Topic, p.Partition))
			}

			if b, ok := cluster.Brokers[partition.Leader]; !ok {
				return broker, NewError(protocol.NewErrNoLeader(t.Topic, p.Partition))
			} else if broker.ID < 0 {
				broker = b
			} else if b.ID != broker.ID {
				return broker, NewError(fmt.Errorf("mismatching leaders (%d!=%d)", b.ID, broker.ID))
			}
		}
	}

	return broker, nil
}

type RequestTopic struct {
	Topic      string             `kafka:"min=v0,max=v11"`
	Partitions []RequestPartition `kafka:"min=v0,max=v11"`
}

type RequestPartition struct {
	Partition          int32 `kafka:"min=v0,max=v11"`
	CurrentLeaderEpoch int32 `kafka:"min=v9,max=v11"`
	FetchOffset        int64 `kafka:"min=v0,max=v11"`
	LogStartOffset     int64 `kafka:"min=v5,max=v11"`
	PartitionMaxBytes  int32 `kafka:"min=v0,max=v11"`
}

type RequestForgottenTopic struct {
	Topic      string  `kafka:"min=v7,max=v11"`
	Partitions []int32 `kafka:"min=v7,max=v11"`
}

type Response struct {
	ThrottleTimeMs int32           `kafka:"min=v1,max=v11"`
	ErrorCode      int16           `kafka:"min=v7,max=v11"`
	SessionID      int32           `kafka:"min=v7,max=v11"`
	Topics         []ResponseTopic `kafka:"min=v0,max=v11"`
}

func (r *Response) ApiKey() protocol.ApiKey { return protocol.Fetch }

type ResponseTopic struct {
	Topic      string              `kafka:"min=v0,max=v11"`
	Partitions []ResponsePartition `kafka:"min=v0,max=v11"`
}

type ResponsePartition struct {
	Partition            int32                 `kafka:"min=v0,max=v11"`
	ErrorCode            int16                 `kafka:"min=v0,max=v11"`
	HighWatermark        int64                 `kafka:"min=v0,max=v11"`
	LastStableOffset     int64                 `kafka:"min=v4,max=v11"`
	LogStartOffset       int64                 `kafka:"min=v5,max=v11"`
	AbortedTransactions  []ResponseTransaction `kafka:"min=v4,max=v11"`
	PreferredReadReplica int32                 `kafka:"min=v11,max=v11"`
	RecordSet            protocol.RecordSet    `kafka:"min=v0,max=v11"`
}

type ResponseTransaction struct {
	ProducerID  int64 `kafka:"min=v4,max=v11"`
	FirstOffset int64 `kafka:"min=v4,max=v11"`
}

var (
	_ protocol.BrokerMessage = (*Request)(nil)
)

type Error struct {
	Err error
}

func NewError(err error) *Error {
	return &Error{Err: err}
}

func (e *Error) Error() string {
	return fmt.Sprintf("fetch request error: %v", e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}
