package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/endtxn"
)

// EndTxnRequest represets a request sent to a kafka broker to end a transaction.
type EndTxnRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The transactional id key.
	TransactionalID string

	// The Producer ID (PID) for the current producer session
	ProducerID int

	// The epoch associated with the current producer session for the given PID
	ProducerEpoch int

	// Committed should be set to true if the transaction was committed, false otherwise.
	Committed bool
}

// EndTxnResponse represents a resposne from a kafka broker to an end transaction request.
type EndTxnResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Error is non-nil if an error occureda and contains the kafka error code.
	// Programs may use the standard errors.Is function to test the error
	// against kafka error codes.
	Error error
}

// EndTxn sends an EndTxn request to a kafka broker and returns its response.
func (c *Client) EndTxn(ctx context.Context, req *EndTxnRequest) (*EndTxnResponse, error) {
	m, err := c.roundTrip(ctx, req.Addr, &endtxn.Request{
		TransactionalID: req.TransactionalID,
		ProducerID:      int64(req.ProducerID),
		ProducerEpoch:   int16(req.ProducerEpoch),
		Committed:       req.Committed,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).EndTxn: %w", err)
	}

	r := m.(*endtxn.Response)

	res := &EndTxnResponse{
		Throttle: makeDuration(r.ThrottleTimeMs),
		Error:    makeError(r.ErrorCode, ""),
	}

	return res, nil
}
