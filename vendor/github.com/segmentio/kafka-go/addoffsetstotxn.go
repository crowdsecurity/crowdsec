package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/addoffsetstotxn"
)

// AddOffsetsToTxnRequest is the request structure for the AddOffsetsToTxn function.
type AddOffsetsToTxnRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The transactional id key
	TransactionalID string

	// The Producer ID (PID) for the current producer session;
	// received from an InitProducerID request.
	ProducerID int

	// The epoch associated with the current producer session for the given PID
	ProducerEpoch int

	// The unique group identifier.
	GroupID string
}

// AddOffsetsToTxnResponse is the response structure for the AddOffsetsToTxn function.
type AddOffsetsToTxnResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// An error that may have occurred when attempting to add the offsets
	// to a transaction.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Error error
}

// AddOffsetsToTnx sends an add offsets to txn request to a kafka broker and returns the response.
func (c *Client) AddOffsetsToTxn(
	ctx context.Context,
	req *AddOffsetsToTxnRequest,
) (*AddOffsetsToTxnResponse, error) {
	m, err := c.roundTrip(ctx, req.Addr, &addoffsetstotxn.Request{
		TransactionalID: req.TransactionalID,
		ProducerID:      int64(req.ProducerID),
		ProducerEpoch:   int16(req.ProducerEpoch),
		GroupID:         req.GroupID,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).AddOffsetsToTxn: %w", err)
	}

	r := m.(*addoffsetstotxn.Response)

	res := &AddOffsetsToTxnResponse{
		Throttle: makeDuration(r.ThrottleTimeMs),
		Error:    makeError(r.ErrorCode, ""),
	}

	return res, nil
}
