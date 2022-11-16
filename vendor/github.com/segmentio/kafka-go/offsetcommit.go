package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/offsetcommit"
)

// OffsetCommit represent the commit of an offset to a partition.
//
// The extra metadata is opaque to the kafka protocol, it is intended to hold
// information like an identifier for the process that committed the offset,
// or the time at which the commit was made.
type OffsetCommit struct {
	Partition int
	Offset    int64
	Metadata  string
}

// OffsetCommitRequest represents a request sent to a kafka broker to commit
// offsets for a partition.
type OffsetCommitRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// ID of the consumer group to publish the offsets for.
	GroupID string

	// ID of the consumer group generation.
	GenerationID int

	// ID of the group member submitting the offsets.
	MemberID string

	// ID of the group instance.
	InstanceID string

	// Set of topic partitions to publish the offsets for.
	//
	// Not that offset commits need to be submitted to the broker acting as the
	// group coordinator. This will be automatically resolved by the transport.
	Topics map[string][]OffsetCommit
}

// OffsetFetchResponse represents a response from a kafka broker to an offset
// commit request.
type OffsetCommitResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Set of topic partitions that the kafka broker has accepted offset commits
	// for.
	Topics map[string][]OffsetCommitPartition
}

// OffsetFetchPartition represents the state of a single partition in responses
// to committing offsets.
type OffsetCommitPartition struct {
	// ID of the partition.
	Partition int

	// An error that may have occurred while attempting to publish consumer
	// group offsets for this partition.
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker. Programs may use the standard errors.Is
	// function to test the error against kafka error codes.
	Error error
}

// OffsetCommit sends an offset commit request to a kafka broker and returns the
// response.
func (c *Client) OffsetCommit(ctx context.Context, req *OffsetCommitRequest) (*OffsetCommitResponse, error) {
	now := time.Now().UnixNano() / int64(time.Millisecond)
	topics := make([]offsetcommit.RequestTopic, 0, len(req.Topics))

	for topicName, commits := range req.Topics {
		partitions := make([]offsetcommit.RequestPartition, len(commits))

		for i, c := range commits {
			partitions[i] = offsetcommit.RequestPartition{
				PartitionIndex:    int32(c.Partition),
				CommittedOffset:   c.Offset,
				CommittedMetadata: c.Metadata,
				// This field existed in v1 of the OffsetCommit API, setting it
				// to the current timestamp is probably a safe thing to do, but
				// it is hard to tell.
				CommitTimestamp: now,
			}
		}

		topics = append(topics, offsetcommit.RequestTopic{
			Name:       topicName,
			Partitions: partitions,
		})
	}

	m, err := c.roundTrip(ctx, req.Addr, &offsetcommit.Request{
		GroupID:         req.GroupID,
		GenerationID:    int32(req.GenerationID),
		MemberID:        req.MemberID,
		GroupInstanceID: req.InstanceID,
		Topics:          topics,
		// Hardcoded retention; this field existed between v2 and v4 of the
		// OffsetCommit API, we would have to figure out a way to give the
		// client control over the API version being used to support configuring
		// it in the request object.
		RetentionTimeMs: int64((24 * time.Hour) / time.Millisecond),
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).OffsetCommit: %w", err)
	}
	r := m.(*offsetcommit.Response)

	res := &OffsetCommitResponse{
		Throttle: makeDuration(r.ThrottleTimeMs),
		Topics:   make(map[string][]OffsetCommitPartition, len(r.Topics)),
	}

	for _, topic := range r.Topics {
		partitions := make([]OffsetCommitPartition, len(topic.Partitions))

		for i, p := range topic.Partitions {
			partitions[i] = OffsetCommitPartition{
				Partition: int(p.PartitionIndex),
				Error:     makeError(p.ErrorCode, ""),
			}
		}

		res.Topics[topic.Name] = partitions
	}

	return res, nil
}

type offsetCommitRequestV2Partition struct {
	// Partition ID
	Partition int32

	// Offset to be committed
	Offset int64

	// Metadata holds any associated metadata the client wants to keep
	Metadata string
}

func (t offsetCommitRequestV2Partition) size() int32 {
	return sizeofInt32(t.Partition) +
		sizeofInt64(t.Offset) +
		sizeofString(t.Metadata)
}

func (t offsetCommitRequestV2Partition) writeTo(wb *writeBuffer) {
	wb.writeInt32(t.Partition)
	wb.writeInt64(t.Offset)
	wb.writeString(t.Metadata)
}

type offsetCommitRequestV2Topic struct {
	// Topic name
	Topic string

	// Partitions to commit offsets
	Partitions []offsetCommitRequestV2Partition
}

func (t offsetCommitRequestV2Topic) size() int32 {
	return sizeofString(t.Topic) +
		sizeofArray(len(t.Partitions), func(i int) int32 { return t.Partitions[i].size() })
}

func (t offsetCommitRequestV2Topic) writeTo(wb *writeBuffer) {
	wb.writeString(t.Topic)
	wb.writeArray(len(t.Partitions), func(i int) { t.Partitions[i].writeTo(wb) })
}

type offsetCommitRequestV2 struct {
	// GroupID holds the unique group identifier
	GroupID string

	// GenerationID holds the generation of the group.
	GenerationID int32

	// MemberID assigned by the group coordinator
	MemberID string

	// RetentionTime holds the time period in ms to retain the offset.
	RetentionTime int64

	// Topics to commit offsets
	Topics []offsetCommitRequestV2Topic
}

func (t offsetCommitRequestV2) size() int32 {
	return sizeofString(t.GroupID) +
		sizeofInt32(t.GenerationID) +
		sizeofString(t.MemberID) +
		sizeofInt64(t.RetentionTime) +
		sizeofArray(len(t.Topics), func(i int) int32 { return t.Topics[i].size() })
}

func (t offsetCommitRequestV2) writeTo(wb *writeBuffer) {
	wb.writeString(t.GroupID)
	wb.writeInt32(t.GenerationID)
	wb.writeString(t.MemberID)
	wb.writeInt64(t.RetentionTime)
	wb.writeArray(len(t.Topics), func(i int) { t.Topics[i].writeTo(wb) })
}

type offsetCommitResponseV2PartitionResponse struct {
	Partition int32

	// ErrorCode holds response error code
	ErrorCode int16
}

func (t offsetCommitResponseV2PartitionResponse) size() int32 {
	return sizeofInt32(t.Partition) +
		sizeofInt16(t.ErrorCode)
}

func (t offsetCommitResponseV2PartitionResponse) writeTo(wb *writeBuffer) {
	wb.writeInt32(t.Partition)
	wb.writeInt16(t.ErrorCode)
}

func (t *offsetCommitResponseV2PartitionResponse) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readInt32(r, size, &t.Partition); err != nil {
		return
	}
	if remain, err = readInt16(r, remain, &t.ErrorCode); err != nil {
		return
	}
	return
}

type offsetCommitResponseV2Response struct {
	Topic              string
	PartitionResponses []offsetCommitResponseV2PartitionResponse
}

func (t offsetCommitResponseV2Response) size() int32 {
	return sizeofString(t.Topic) +
		sizeofArray(len(t.PartitionResponses), func(i int) int32 { return t.PartitionResponses[i].size() })
}

func (t offsetCommitResponseV2Response) writeTo(wb *writeBuffer) {
	wb.writeString(t.Topic)
	wb.writeArray(len(t.PartitionResponses), func(i int) { t.PartitionResponses[i].writeTo(wb) })
}

func (t *offsetCommitResponseV2Response) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readString(r, size, &t.Topic); err != nil {
		return
	}

	fn := func(r *bufio.Reader, withSize int) (fnRemain int, fnErr error) {
		item := offsetCommitResponseV2PartitionResponse{}
		if fnRemain, fnErr = (&item).readFrom(r, withSize); fnErr != nil {
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

type offsetCommitResponseV2 struct {
	Responses []offsetCommitResponseV2Response
}

func (t offsetCommitResponseV2) size() int32 {
	return sizeofArray(len(t.Responses), func(i int) int32 { return t.Responses[i].size() })
}

func (t offsetCommitResponseV2) writeTo(wb *writeBuffer) {
	wb.writeArray(len(t.Responses), func(i int) { t.Responses[i].writeTo(wb) })
}

func (t *offsetCommitResponseV2) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	fn := func(r *bufio.Reader, withSize int) (fnRemain int, fnErr error) {
		item := offsetCommitResponseV2Response{}
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
