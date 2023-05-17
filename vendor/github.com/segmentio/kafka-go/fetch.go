package kafka

import (
	"context"
	"fmt"
	"math"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol"
	fetchAPI "github.com/segmentio/kafka-go/protocol/fetch"
)

// FetchRequest represents a request sent to a kafka broker to retrieve records
// from a topic partition.
type FetchRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// Topic, partition, and offset to retrieve records from. The offset may be
	// one of the special FirstOffset or LastOffset constants, in which case the
	// request will automatically discover the first or last offset of the
	// partition and submit the request for these.
	Topic     string
	Partition int
	Offset    int64

	// Size and time limits of the response returned by the broker.
	MinBytes int64
	MaxBytes int64
	MaxWait  time.Duration

	// The isolation level for the request.
	//
	// Defaults to ReadUncommitted.
	//
	// This field requires the kafka broker to support the Fetch API in version
	// 4 or above (otherwise the value is ignored).
	IsolationLevel IsolationLevel
}

// FetchResponse represents a response from a kafka broker to a fetch request.
type FetchResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// The topic and partition that the response came for (will match the values
	// in the request).
	Topic     string
	Partition int

	// Informations about the topic partition layout returned from the broker.
	//
	// LastStableOffset requires the kafka broker to support the Fetch API in
	// version 4 or above (otherwise the value is zero).
	//
	/// LogStartOffset requires the kafka broker to support the Fetch API in
	// version 5 or above (otherwise the value is zero).
	HighWatermark    int64
	LastStableOffset int64
	LogStartOffset   int64

	// An error that may have occurred while attempting to fetch the records.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error

	// The set of records returned in the response.
	//
	// The program is expected to call the RecordSet's Close method when it
	// finished reading the records.
	//
	// Note that kafka may return record batches that start at an offset before
	// the one that was requested. It is the program's responsibility to skip
	// the offsets that it is not interested in.
	Records RecordReader
}

// Fetch sends a fetch request to a kafka broker and returns the response.
//
// If the broker returned an invalid response with no topics, an error wrapping
// protocol.ErrNoTopic is returned.
//
// If the broker returned an invalid response with no partitions, an error
// wrapping ErrNoPartitions is returned.
func (c *Client) Fetch(ctx context.Context, req *FetchRequest) (*FetchResponse, error) {
	timeout := c.timeout(ctx, math.MaxInt64)
	maxWait := req.maxWait()

	if maxWait < timeout {
		timeout = maxWait
	}

	offset := req.Offset
	switch offset {
	case FirstOffset, LastOffset:
		topic, partition := req.Topic, req.Partition

		r, err := c.ListOffsets(ctx, &ListOffsetsRequest{
			Addr: req.Addr,
			Topics: map[string][]OffsetRequest{
				topic: {{
					Partition: partition,
					Timestamp: offset,
				}},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("kafka.(*Client).Fetch: %w", err)
		}

		for _, p := range r.Topics[topic] {
			if p.Partition == partition {
				if p.Error != nil {
					return nil, fmt.Errorf("kafka.(*Client).Fetch: %w", p.Error)
				}
				switch offset {
				case FirstOffset:
					offset = p.FirstOffset
				case LastOffset:
					offset = p.LastOffset
				}
				break
			}
		}
	}

	m, err := c.roundTrip(ctx, req.Addr, &fetchAPI.Request{
		ReplicaID:      -1,
		MaxWaitTime:    milliseconds(timeout),
		MinBytes:       int32(req.MinBytes),
		MaxBytes:       int32(req.MaxBytes),
		IsolationLevel: int8(req.IsolationLevel),
		SessionID:      -1,
		SessionEpoch:   -1,
		Topics: []fetchAPI.RequestTopic{{
			Topic: req.Topic,
			Partitions: []fetchAPI.RequestPartition{{
				Partition:          int32(req.Partition),
				CurrentLeaderEpoch: -1,
				FetchOffset:        offset,
				LogStartOffset:     -1,
				PartitionMaxBytes:  int32(req.MaxBytes),
			}},
		}},
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).Fetch: %w", err)
	}

	res := m.(*fetchAPI.Response)
	if len(res.Topics) == 0 {
		return nil, fmt.Errorf("kafka.(*Client).Fetch: %w", protocol.ErrNoTopic)
	}
	topic := &res.Topics[0]
	if len(topic.Partitions) == 0 {
		return nil, fmt.Errorf("kafka.(*Client).Fetch: %w", protocol.ErrNoPartition)
	}
	partition := &topic.Partitions[0]

	ret := &FetchResponse{
		Throttle:         makeDuration(res.ThrottleTimeMs),
		Topic:            topic.Topic,
		Partition:        int(partition.Partition),
		Error:            makeError(res.ErrorCode, ""),
		HighWatermark:    partition.HighWatermark,
		LastStableOffset: partition.LastStableOffset,
		LogStartOffset:   partition.LogStartOffset,
		Records:          partition.RecordSet.Records,
	}

	if partition.ErrorCode != 0 {
		ret.Error = makeError(partition.ErrorCode, "")
	}

	if ret.Records == nil {
		ret.Records = NewRecordReader()
	}

	return ret, nil
}

func (req *FetchRequest) maxWait() time.Duration {
	if req.MaxWait > 0 {
		return req.MaxWait
	}
	return defaultMaxWait
}

type fetchRequestV2 struct {
	ReplicaID   int32
	MaxWaitTime int32
	MinBytes    int32
	Topics      []fetchRequestTopicV2
}

func (r fetchRequestV2) size() int32 {
	return 4 + 4 + 4 + sizeofArray(len(r.Topics), func(i int) int32 { return r.Topics[i].size() })
}

func (r fetchRequestV2) writeTo(wb *writeBuffer) {
	wb.writeInt32(r.ReplicaID)
	wb.writeInt32(r.MaxWaitTime)
	wb.writeInt32(r.MinBytes)
	wb.writeArray(len(r.Topics), func(i int) { r.Topics[i].writeTo(wb) })
}

type fetchRequestTopicV2 struct {
	TopicName  string
	Partitions []fetchRequestPartitionV2
}

func (t fetchRequestTopicV2) size() int32 {
	return sizeofString(t.TopicName) +
		sizeofArray(len(t.Partitions), func(i int) int32 { return t.Partitions[i].size() })
}

func (t fetchRequestTopicV2) writeTo(wb *writeBuffer) {
	wb.writeString(t.TopicName)
	wb.writeArray(len(t.Partitions), func(i int) { t.Partitions[i].writeTo(wb) })
}

type fetchRequestPartitionV2 struct {
	Partition   int32
	FetchOffset int64
	MaxBytes    int32
}

func (p fetchRequestPartitionV2) size() int32 {
	return 4 + 8 + 4
}

func (p fetchRequestPartitionV2) writeTo(wb *writeBuffer) {
	wb.writeInt32(p.Partition)
	wb.writeInt64(p.FetchOffset)
	wb.writeInt32(p.MaxBytes)
}

type fetchResponseV2 struct {
	ThrottleTime int32
	Topics       []fetchResponseTopicV2
}

func (r fetchResponseV2) size() int32 {
	return 4 + sizeofArray(len(r.Topics), func(i int) int32 { return r.Topics[i].size() })
}

func (r fetchResponseV2) writeTo(wb *writeBuffer) {
	wb.writeInt32(r.ThrottleTime)
	wb.writeArray(len(r.Topics), func(i int) { r.Topics[i].writeTo(wb) })
}

type fetchResponseTopicV2 struct {
	TopicName  string
	Partitions []fetchResponsePartitionV2
}

func (t fetchResponseTopicV2) size() int32 {
	return sizeofString(t.TopicName) +
		sizeofArray(len(t.Partitions), func(i int) int32 { return t.Partitions[i].size() })
}

func (t fetchResponseTopicV2) writeTo(wb *writeBuffer) {
	wb.writeString(t.TopicName)
	wb.writeArray(len(t.Partitions), func(i int) { t.Partitions[i].writeTo(wb) })
}

type fetchResponsePartitionV2 struct {
	Partition           int32
	ErrorCode           int16
	HighwaterMarkOffset int64
	MessageSetSize      int32
	MessageSet          messageSet
}

func (p fetchResponsePartitionV2) size() int32 {
	return 4 + 2 + 8 + 4 + p.MessageSet.size()
}

func (p fetchResponsePartitionV2) writeTo(wb *writeBuffer) {
	wb.writeInt32(p.Partition)
	wb.writeInt16(p.ErrorCode)
	wb.writeInt64(p.HighwaterMarkOffset)
	wb.writeInt32(p.MessageSetSize)
	p.MessageSet.writeTo(wb)
}
