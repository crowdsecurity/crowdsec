package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/initproducerid"
)

// InitProducerIDRequest is the request structure for the InitProducerId function.
type InitProducerIDRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The transactional id key.
	TransactionalID string

	// Time after which a transaction should time out
	TransactionTimeoutMs int

	// The Producer ID (PID).
	// This is used to disambiguate requests if a transactional id is reused following its expiration.
	// Only supported in version >=3 of the request, will be ignore otherwise.
	ProducerID int

	// The producer's current epoch.
	// This will be checked against the producer epoch on the broker,
	// and the request will return an error if they do not match.
	// Only supported in version >=3 of the request, will be ignore otherwise.
	ProducerEpoch int
}

// ProducerSession contains useful information about the producer session from the broker's response.
type ProducerSession struct {
	// The Producer ID (PID) for the current producer session
	ProducerID int

	// The epoch associated with the current producer session for the given PID
	ProducerEpoch int
}

// InitProducerIDResponse is the response structure for the InitProducerId function.
type InitProducerIDResponse struct {
	// The Transaction/Group Coordinator details
	Producer *ProducerSession

	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// An error that may have occurred while attempting to retrieve initProducerId
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker.
	Error error
}

// InitProducerID sends a initProducerId request to a kafka broker and returns the
// response.
func (c *Client) InitProducerID(ctx context.Context, req *InitProducerIDRequest) (*InitProducerIDResponse, error) {
	m, err := c.roundTrip(ctx, req.Addr, &initproducerid.Request{
		TransactionalID:      req.TransactionalID,
		TransactionTimeoutMs: int32(req.TransactionTimeoutMs),
		ProducerID:           int64(req.ProducerID),
		ProducerEpoch:        int16(req.ProducerEpoch),
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).InitProducerId: %w", err)
	}

	res := m.(*initproducerid.Response)

	return &InitProducerIDResponse{
		Producer: &ProducerSession{
			ProducerID:    int(res.ProducerID),
			ProducerEpoch: int(res.ProducerEpoch),
		},
		Throttle: makeDuration(res.ThrottleTimeMs),
		Error:    makeError(res.ErrorCode, ""),
	}, nil
}
