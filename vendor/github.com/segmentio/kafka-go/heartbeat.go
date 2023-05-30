package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	heartbeatAPI "github.com/segmentio/kafka-go/protocol/heartbeat"
)

// HeartbeatRequest represents a heartbeat sent to kafka to indicate consume liveness.
type HeartbeatRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// GroupID is the ID of the group.
	GroupID string

	// GenerationID is the current generation for the group.
	GenerationID int32

	// MemberID is the ID of the group member.
	MemberID string

	// GroupInstanceID is a unique identifier for the consumer.
	GroupInstanceID string
}

// HeartbeatResponse represents a response from a heartbeat request.
type HeartbeatResponse struct {
	// Error is set to non-nil if an error occurred.
	Error error

	// The amount of time that the broker throttled the request.
	//
	// This field will be zero if the kafka broker did not support the
	// Heartbeat API in version 1 or above.
	Throttle time.Duration
}

type heartbeatRequestV0 struct {
	// GroupID holds the unique group identifier
	GroupID string

	// GenerationID holds the generation of the group.
	GenerationID int32

	// MemberID assigned by the group coordinator
	MemberID string
}

// Heartbeat sends a heartbeat request to a kafka broker and returns the response.
func (c *Client) Heartbeat(ctx context.Context, req *HeartbeatRequest) (*HeartbeatResponse, error) {
	m, err := c.roundTrip(ctx, req.Addr, &heartbeatAPI.Request{
		GroupID:         req.GroupID,
		GenerationID:    req.GenerationID,
		MemberID:        req.MemberID,
		GroupInstanceID: req.GroupInstanceID,
	})
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).Heartbeat: %w", err)
	}

	res := m.(*heartbeatAPI.Response)

	ret := &HeartbeatResponse{
		Throttle: makeDuration(res.ThrottleTimeMs),
	}

	if res.ErrorCode != 0 {
		ret.Error = Error(res.ErrorCode)
	}

	return ret, nil
}

func (t heartbeatRequestV0) size() int32 {
	return sizeofString(t.GroupID) +
		sizeofInt32(t.GenerationID) +
		sizeofString(t.MemberID)
}

func (t heartbeatRequestV0) writeTo(wb *writeBuffer) {
	wb.writeString(t.GroupID)
	wb.writeInt32(t.GenerationID)
	wb.writeString(t.MemberID)
}

type heartbeatResponseV0 struct {
	// ErrorCode holds response error code
	ErrorCode int16
}

func (t heartbeatResponseV0) size() int32 {
	return sizeofInt16(t.ErrorCode)
}

func (t heartbeatResponseV0) writeTo(wb *writeBuffer) {
	wb.writeInt16(t.ErrorCode)
}

func (t *heartbeatResponseV0) readFrom(r *bufio.Reader, sz int) (remain int, err error) {
	if remain, err = readInt16(r, sz, &t.ErrorCode); err != nil {
		return
	}
	return
}
