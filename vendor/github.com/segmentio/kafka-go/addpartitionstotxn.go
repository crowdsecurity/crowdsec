package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/addpartitionstotxn"
)

// AddPartitionToTxn represents a partition to be added
// to a transaction.
type AddPartitionToTxn struct {
	// Partition is the ID of a partition to add to the transaction.
	Partition int
}

// AddPartitionsToTxnRequest is the request structure fo the AddPartitionsToTxn function.
type AddPartitionsToTxnRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The transactional id key
	TransactionalID string

	// The Producer ID (PID) for the current producer session;
	// received from an InitProducerID request.
	ProducerID int

	// The epoch associated with the current producer session for the given PID
	ProducerEpoch int

	// Mappings of topic names to lists of partitions.
	Topics map[string][]AddPartitionToTxn
}

// AddPartitionsToTxnResponse is the response structure for the AddPartitionsToTxn function.
type AddPartitionsToTxnResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Mappings of topic names to partitions being added to a transactions.
	Topics map[string][]AddPartitionToTxnPartition
}

// AddPartitionToTxnPartition represents the state of a single partition
// in response to adding to a transaction.
type AddPartitionToTxnPartition struct {
	// The ID of the partition.
	Partition int

	// An error that may have occurred when attempting to add the partition
	// to a transaction.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Error error
}

// AddPartitionsToTnx sends an add partitions to txn request to a kafka broker and returns the response.
func (c *Client) AddPartitionsToTxn(
	ctx context.Context,
	req *AddPartitionsToTxnRequest,
) (*AddPartitionsToTxnResponse, error) {
	protoReq := &addpartitionstotxn.Request{
		TransactionalID: req.TransactionalID,
		ProducerID:      int64(req.ProducerID),
		ProducerEpoch:   int16(req.ProducerEpoch),
	}
	protoReq.Topics = make([]addpartitionstotxn.RequestTopic, 0, len(req.Topics))

	for topic, partitions := range req.Topics {
		reqTopic := addpartitionstotxn.RequestTopic{
			Name:       topic,
			Partitions: make([]int32, len(partitions)),
		}
		for i, partition := range partitions {
			reqTopic.Partitions[i] = int32(partition.Partition)
		}
		protoReq.Topics = append(protoReq.Topics, reqTopic)
	}

	m, err := c.roundTrip(ctx, req.Addr, protoReq)
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).AddPartitionsToTxn: %w", err)
	}

	r := m.(*addpartitionstotxn.Response)

	res := &AddPartitionsToTxnResponse{
		Throttle: makeDuration(r.ThrottleTimeMs),
		Topics:   make(map[string][]AddPartitionToTxnPartition, len(r.Results)),
	}

	for _, result := range r.Results {
		partitions := make([]AddPartitionToTxnPartition, 0, len(result.Results))
		for _, rp := range result.Results {
			partitions = append(partitions, AddPartitionToTxnPartition{
				Partition: int(rp.PartitionIndex),
				Error:     makeError(rp.ErrorCode, ""),
			})
		}
		res.Topics[result.Name] = partitions
	}

	return res, nil
}
