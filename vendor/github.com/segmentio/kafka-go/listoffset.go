package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/listoffsets"
)

// OffsetRequest represents a request to retrieve a single partition offset.
type OffsetRequest struct {
	Partition int
	Timestamp int64
}

// FirstOffsetOf constructs an OffsetRequest which asks for the first offset of
// the parition given as argument.
func FirstOffsetOf(partition int) OffsetRequest {
	return OffsetRequest{Partition: partition, Timestamp: FirstOffset}
}

// LastOffsetOf constructs an OffsetRequest which asks for the last offset of
// the partition given as argument.
func LastOffsetOf(partition int) OffsetRequest {
	return OffsetRequest{Partition: partition, Timestamp: LastOffset}
}

// TimeOffsetOf constructs an OffsetRequest which asks for a partition offset
// at a given time.
func TimeOffsetOf(partition int, at time.Time) OffsetRequest {
	return OffsetRequest{Partition: partition, Timestamp: timestamp(at)}
}

// PartitionOffsets carries information about offsets available in a topic
// partition.
type PartitionOffsets struct {
	Partition   int
	FirstOffset int64
	LastOffset  int64
	Offsets     map[int64]time.Time
	Error       error
}

// ListOffsetsRequest represents a request sent to a kafka broker to list of the
// offsets of topic partitions.
type ListOffsetsRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// A mapping of topic names to list of partitions that the program wishes to
	// get the offsets for.
	Topics map[string][]OffsetRequest

	// The isolation level for the request.
	//
	// Defaults to ReadUncommitted.
	//
	// This field requires the kafka broker to support the ListOffsets API in
	// version 2 or above (otherwise the value is ignored).
	IsolationLevel IsolationLevel
}

// ListOffsetsResponse represents a response from a kafka broker to a offset
// listing request.
type ListOffsetsResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Mappings of topics names to partition offsets, there will be one entry
	// for each topic in the request.
	Topics map[string][]PartitionOffsets
}

// ListOffsets sends an offset request to a kafka broker and returns the
// response.
func (c *Client) ListOffsets(ctx context.Context, req *ListOffsetsRequest) (*ListOffsetsResponse, error) {
	type topicPartition struct {
		topic     string
		partition int
	}

	partitionOffsets := make(map[topicPartition]PartitionOffsets)

	for topicName, requests := range req.Topics {
		for _, r := range requests {
			key := topicPartition{
				topic:     topicName,
				partition: r.Partition,
			}

			partition, ok := partitionOffsets[key]
			if !ok {
				partition = PartitionOffsets{
					Partition:   r.Partition,
					FirstOffset: -1,
					LastOffset:  -1,
					Offsets:     make(map[int64]time.Time),
				}
			}

			switch r.Timestamp {
			case FirstOffset:
				partition.FirstOffset = 0
			case LastOffset:
				partition.LastOffset = 0
			}

			partitionOffsets[topicPartition{
				topic:     topicName,
				partition: r.Partition,
			}] = partition
		}
	}

	topics := make([]listoffsets.RequestTopic, 0, len(req.Topics))

	for topicName, requests := range req.Topics {
		partitions := make([]listoffsets.RequestPartition, len(requests))

		for i, r := range requests {
			partitions[i] = listoffsets.RequestPartition{
				Partition:          int32(r.Partition),
				CurrentLeaderEpoch: -1,
				Timestamp:          r.Timestamp,
			}
		}

		topics = append(topics, listoffsets.RequestTopic{
			Topic:      topicName,
			Partitions: partitions,
		})
	}

	m, err := c.roundTrip(ctx, req.Addr, &listoffsets.Request{
		ReplicaID:      -1,
		IsolationLevel: int8(req.IsolationLevel),
		Topics:         topics,
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).ListOffsets: %w", err)
	}

	res := m.(*listoffsets.Response)
	ret := &ListOffsetsResponse{
		Throttle: makeDuration(res.ThrottleTimeMs),
		Topics:   make(map[string][]PartitionOffsets, len(res.Topics)),
	}

	for _, t := range res.Topics {
		for _, p := range t.Partitions {
			key := topicPartition{
				topic:     t.Topic,
				partition: int(p.Partition),
			}

			partition := partitionOffsets[key]

			switch p.Timestamp {
			case FirstOffset:
				partition.FirstOffset = p.Offset
			case LastOffset:
				partition.LastOffset = p.Offset
			default:
				partition.Offsets[p.Offset] = makeTime(p.Timestamp)
			}

			if p.ErrorCode != 0 {
				partition.Error = Error(p.ErrorCode)
			}

			partitionOffsets[key] = partition
		}
	}

	for key, partition := range partitionOffsets {
		ret.Topics[key.topic] = append(ret.Topics[key.topic], partition)
	}

	return ret, nil
}

type listOffsetRequestV1 struct {
	ReplicaID int32
	Topics    []listOffsetRequestTopicV1
}

func (r listOffsetRequestV1) size() int32 {
	return 4 + sizeofArray(len(r.Topics), func(i int) int32 { return r.Topics[i].size() })
}

func (r listOffsetRequestV1) writeTo(wb *writeBuffer) {
	wb.writeInt32(r.ReplicaID)
	wb.writeArray(len(r.Topics), func(i int) { r.Topics[i].writeTo(wb) })
}

type listOffsetRequestTopicV1 struct {
	TopicName  string
	Partitions []listOffsetRequestPartitionV1
}

func (t listOffsetRequestTopicV1) size() int32 {
	return sizeofString(t.TopicName) +
		sizeofArray(len(t.Partitions), func(i int) int32 { return t.Partitions[i].size() })
}

func (t listOffsetRequestTopicV1) writeTo(wb *writeBuffer) {
	wb.writeString(t.TopicName)
	wb.writeArray(len(t.Partitions), func(i int) { t.Partitions[i].writeTo(wb) })
}

type listOffsetRequestPartitionV1 struct {
	Partition int32
	Time      int64
}

func (p listOffsetRequestPartitionV1) size() int32 {
	return 4 + 8
}

func (p listOffsetRequestPartitionV1) writeTo(wb *writeBuffer) {
	wb.writeInt32(p.Partition)
	wb.writeInt64(p.Time)
}

type listOffsetResponseV1 []listOffsetResponseTopicV1

func (r listOffsetResponseV1) size() int32 {
	return sizeofArray(len(r), func(i int) int32 { return r[i].size() })
}

func (r listOffsetResponseV1) writeTo(wb *writeBuffer) {
	wb.writeArray(len(r), func(i int) { r[i].writeTo(wb) })
}

type listOffsetResponseTopicV1 struct {
	TopicName        string
	PartitionOffsets []partitionOffsetV1
}

func (t listOffsetResponseTopicV1) size() int32 {
	return sizeofString(t.TopicName) +
		sizeofArray(len(t.PartitionOffsets), func(i int) int32 { return t.PartitionOffsets[i].size() })
}

func (t listOffsetResponseTopicV1) writeTo(wb *writeBuffer) {
	wb.writeString(t.TopicName)
	wb.writeArray(len(t.PartitionOffsets), func(i int) { t.PartitionOffsets[i].writeTo(wb) })
}

type partitionOffsetV1 struct {
	Partition int32
	ErrorCode int16
	Timestamp int64
	Offset    int64
}

func (p partitionOffsetV1) size() int32 {
	return 4 + 2 + 8 + 8
}

func (p partitionOffsetV1) writeTo(wb *writeBuffer) {
	wb.writeInt32(p.Partition)
	wb.writeInt16(p.ErrorCode)
	wb.writeInt64(p.Timestamp)
	wb.writeInt64(p.Offset)
}

func (p *partitionOffsetV1) readFrom(r *bufio.Reader, sz int) (remain int, err error) {
	if remain, err = readInt32(r, sz, &p.Partition); err != nil {
		return
	}
	if remain, err = readInt16(r, remain, &p.ErrorCode); err != nil {
		return
	}
	if remain, err = readInt64(r, remain, &p.Timestamp); err != nil {
		return
	}
	if remain, err = readInt64(r, remain, &p.Offset); err != nil {
		return
	}
	return
}
