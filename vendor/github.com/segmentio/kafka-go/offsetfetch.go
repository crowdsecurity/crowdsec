package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/offsetfetch"
)

// OffsetFetchRequest represents a request sent to a kafka broker to read the
// currently committed offsets of topic partitions.
type OffsetFetchRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// ID of the consumer group to retrieve the offsets for.
	GroupID string

	// Set of topic partitions to retrieve the offsets for.
	Topics map[string][]int
}

// OffsetFetchResponse represents a response from a kafka broker to an offset
// fetch request.
type OffsetFetchResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Set of topic partitions that the kafka broker has returned offsets for.
	Topics map[string][]OffsetFetchPartition

	// An error that may have occurred while attempting to retrieve consumer
	// group offsets.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error
}

// OffsetFetchPartition represents the state of a single partition in a consumer
// group.
type OffsetFetchPartition struct {
	// ID of the partition.
	Partition int

	// Last committed offsets on the partition when the request was served by
	// the kafka broker.
	CommittedOffset int64

	// Consumer group metadata for this partition.
	Metadata string

	// An error that may have occurred while attempting to retrieve consumer
	// group offsets for this partition.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error
}

// OffsetFetch sends an offset fetch request to a kafka broker and returns the
// response.
func (c *Client) OffsetFetch(ctx context.Context, req *OffsetFetchRequest) (*OffsetFetchResponse, error) {
	topics := make([]offsetfetch.RequestTopic, 0, len(req.Topics))

	for topicName, partitions := range req.Topics {
		indexes := make([]int32, len(partitions))

		for i, p := range partitions {
			indexes[i] = int32(p)
		}

		topics = append(topics, offsetfetch.RequestTopic{
			Name:             topicName,
			PartitionIndexes: indexes,
		})
	}

	m, err := c.roundTrip(ctx, req.Addr, &offsetfetch.Request{
		GroupID: req.GroupID,
		Topics:  topics,
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).OffsetFetch: %w", err)
	}

	res := m.(*offsetfetch.Response)
	ret := &OffsetFetchResponse{
		Throttle: makeDuration(res.ThrottleTimeMs),
		Topics:   make(map[string][]OffsetFetchPartition, len(res.Topics)),
		Error:    makeError(res.ErrorCode, ""),
	}

	for _, t := range res.Topics {
		partitions := make([]OffsetFetchPartition, len(t.Partitions))

		for i, p := range t.Partitions {
			partitions[i] = OffsetFetchPartition{
				Partition:       int(p.PartitionIndex),
				CommittedOffset: p.CommittedOffset,
				Metadata:        p.Metadata,
				Error:           makeError(p.ErrorCode, ""),
			}
		}

		ret.Topics[t.Name] = partitions
	}

	return ret, nil
}

type offsetFetchRequestV1Topic struct {
	// Topic name
	Topic string

	// Partitions to fetch offsets
	Partitions []int32
}

func (t offsetFetchRequestV1Topic) size() int32 {
	return sizeofString(t.Topic) +
		sizeofInt32Array(t.Partitions)
}

func (t offsetFetchRequestV1Topic) writeTo(wb *writeBuffer) {
	wb.writeString(t.Topic)
	wb.writeInt32Array(t.Partitions)
}

type offsetFetchRequestV1 struct {
	// GroupID holds the unique group identifier
	GroupID string

	// Topics to fetch offsets.
	Topics []offsetFetchRequestV1Topic
}

func (t offsetFetchRequestV1) size() int32 {
	return sizeofString(t.GroupID) +
		sizeofArray(len(t.Topics), func(i int) int32 { return t.Topics[i].size() })
}

func (t offsetFetchRequestV1) writeTo(wb *writeBuffer) {
	wb.writeString(t.GroupID)
	wb.writeArray(len(t.Topics), func(i int) { t.Topics[i].writeTo(wb) })
}

type offsetFetchResponseV1PartitionResponse struct {
	// Partition ID
	Partition int32

	// Offset of last committed message
	Offset int64

	// Metadata client wants to keep
	Metadata string

	// ErrorCode holds response error code
	ErrorCode int16
}

func (t offsetFetchResponseV1PartitionResponse) size() int32 {
	return sizeofInt32(t.Partition) +
		sizeofInt64(t.Offset) +
		sizeofString(t.Metadata) +
		sizeofInt16(t.ErrorCode)
}

func (t offsetFetchResponseV1PartitionResponse) writeTo(wb *writeBuffer) {
	wb.writeInt32(t.Partition)
	wb.writeInt64(t.Offset)
	wb.writeString(t.Metadata)
	wb.writeInt16(t.ErrorCode)
}

func (t *offsetFetchResponseV1PartitionResponse) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readInt32(r, size, &t.Partition); err != nil {
		return
	}
	if remain, err = readInt64(r, remain, &t.Offset); err != nil {
		return
	}
	if remain, err = readString(r, remain, &t.Metadata); err != nil {
		return
	}
	if remain, err = readInt16(r, remain, &t.ErrorCode); err != nil {
		return
	}
	return
}

type offsetFetchResponseV1Response struct {
	// Topic name
	Topic string

	// PartitionResponses holds offsets by partition
	PartitionResponses []offsetFetchResponseV1PartitionResponse
}

func (t offsetFetchResponseV1Response) size() int32 {
	return sizeofString(t.Topic) +
		sizeofArray(len(t.PartitionResponses), func(i int) int32 { return t.PartitionResponses[i].size() })
}

func (t offsetFetchResponseV1Response) writeTo(wb *writeBuffer) {
	wb.writeString(t.Topic)
	wb.writeArray(len(t.PartitionResponses), func(i int) { t.PartitionResponses[i].writeTo(wb) })
}

func (t *offsetFetchResponseV1Response) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readString(r, size, &t.Topic); err != nil {
		return
	}

	fn := func(r *bufio.Reader, size int) (fnRemain int, fnErr error) {
		item := offsetFetchResponseV1PartitionResponse{}
		if fnRemain, fnErr = (&item).readFrom(r, size); err != nil {
			return
		}
		t.PartitionResponses = append(t.PartitionResponses, item)
		return
	}
	if remain, err = readArrayWith(r, remain, fn); err != nil {
		return
	}

	return
}

type offsetFetchResponseV1 struct {
	// Responses holds topic partition offsets
	Responses []offsetFetchResponseV1Response
}

func (t offsetFetchResponseV1) size() int32 {
	return sizeofArray(len(t.Responses), func(i int) int32 { return t.Responses[i].size() })
}

func (t offsetFetchResponseV1) writeTo(wb *writeBuffer) {
	wb.writeArray(len(t.Responses), func(i int) { t.Responses[i].writeTo(wb) })
}

func (t *offsetFetchResponseV1) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	fn := func(r *bufio.Reader, withSize int) (fnRemain int, fnErr error) {
		item := offsetFetchResponseV1Response{}
		if fnRemain, fnErr = (&item).readFrom(r, withSize); fnErr != nil {
			return
		}
		t.Responses = append(t.Responses, item)
		return
	}
	if remain, err = readArrayWith(r, size, fn); err != nil {
		return
	}

	return
}
