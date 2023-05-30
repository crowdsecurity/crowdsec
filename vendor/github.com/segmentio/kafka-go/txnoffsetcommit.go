package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/txnoffsetcommit"
)

// TxnOffsetCommitRequest represents a request sent to a kafka broker to commit
// offsets for a partition within a transaction.
type TxnOffsetCommitRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The transactional id key.
	TransactionalID string

	// ID of the consumer group to publish the offsets for.
	GroupID string

	// The Producer ID (PID) for the current producer session;
	// received from an InitProducerID request.
	ProducerID int

	// The epoch associated with the current producer session for the given PID
	ProducerEpoch int

	// GenerationID is the current generation for the group.
	GenerationID int

	// ID of the group member submitting the offsets.
	MemberID string

	// GroupInstanceID is a unique identifier for the consumer.
	GroupInstanceID string

	// Set of topic partitions to publish the offsets for.
	//
	// Not that offset commits need to be submitted to the broker acting as the
	// group coordinator. This will be automatically resolved by the transport.
	Topics map[string][]TxnOffsetCommit
}

// TxnOffsetCommit represent the commit of an offset to a partition within a transaction.
//
// The extra metadata is opaque to the kafka protocol, it is intended to hold
// information like an identifier for the process that committed the offset,
// or the time at which the commit was made.
type TxnOffsetCommit struct {
	Partition int
	Offset    int64
	Metadata  string
}

// TxnOffsetFetchResponse represents a response from a kafka broker to an offset
// commit request within a transaction.
type TxnOffsetCommitResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Set of topic partitions that the kafka broker has accepted offset commits
	// for.
	Topics map[string][]TxnOffsetCommitPartition
}

// TxnOffsetFetchPartition represents the state of a single partition in responses
// to committing offsets within a  transaction.
type TxnOffsetCommitPartition struct {
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

// TxnOffsetCommit sends an txn offset commit request to a kafka broker and returns the
// response.
func (c *Client) TxnOffsetCommit(
	ctx context.Context,
	req *TxnOffsetCommitRequest,
) (*TxnOffsetCommitResponse, error) {
	protoReq := &txnoffsetcommit.Request{
		TransactionalID: req.TransactionalID,
		GroupID:         req.GroupID,
		ProducerID:      int64(req.ProducerID),
		ProducerEpoch:   int16(req.ProducerEpoch),
		GenerationID:    int32(req.GenerationID),
		MemberID:        req.MemberID,
		GroupInstanceID: req.GroupInstanceID,
		Topics:          make([]txnoffsetcommit.RequestTopic, 0, len(req.Topics)),
	}

	for topic, partitions := range req.Topics {
		parts := make([]txnoffsetcommit.RequestPartition, len(partitions))
		for i, partition := range partitions {
			parts[i] = txnoffsetcommit.RequestPartition{
				Partition:         int32(partition.Partition),
				CommittedOffset:   int64(partition.Offset),
				CommittedMetadata: partition.Metadata,
			}
		}
		t := txnoffsetcommit.RequestTopic{
			Name:       topic,
			Partitions: parts,
		}

		protoReq.Topics = append(protoReq.Topics, t)
	}

	m, err := c.roundTrip(ctx, req.Addr, protoReq)
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).TxnOffsetCommit: %w", err)
	}

	r := m.(*txnoffsetcommit.Response)

	res := &TxnOffsetCommitResponse{
		Throttle: makeDuration(r.ThrottleTimeMs),
		Topics:   make(map[string][]TxnOffsetCommitPartition, len(r.Topics)),
	}

	for _, topic := range r.Topics {
		partitions := make([]TxnOffsetCommitPartition, 0, len(topic.Partitions))
		for _, partition := range topic.Partitions {
			partitions = append(partitions, TxnOffsetCommitPartition{
				Partition: int(partition.Partition),
				Error:     makeError(partition.ErrorCode, ""),
			})
		}
		res.Topics[topic.Name] = partitions
	}

	return res, nil
}
