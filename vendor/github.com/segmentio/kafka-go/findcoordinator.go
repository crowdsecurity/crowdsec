package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/findcoordinator"
)

// CoordinatorKeyType is used to specify the type of coordinator to look for.
type CoordinatorKeyType int8

const (
	// CoordinatorKeyTypeConsumer type is used when looking for a Group coordinator.
	CoordinatorKeyTypeConsumer CoordinatorKeyType = 0

	// CoordinatorKeyTypeTransaction type is used when looking for a Transaction coordinator.
	CoordinatorKeyTypeTransaction CoordinatorKeyType = 1
)

// FindCoordinatorRequest is the request structure for the FindCoordinator function.
type FindCoordinatorRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The coordinator key.
	Key string

	// The coordinator key type. (Group, transaction, etc.)
	KeyType CoordinatorKeyType
}

// FindCoordinatorResponseCoordinator contains details about the found coordinator.
type FindCoordinatorResponseCoordinator struct {
	// NodeID holds the broker id.
	NodeID int

	// Host of the broker
	Host string

	// Port on which broker accepts requests
	Port int
}

// FindCoordinatorResponse is the response structure for the FindCoordinator function.
type FindCoordinatorResponse struct {
	// The Transaction/Group Coordinator details
	Coordinator *FindCoordinatorResponseCoordinator

	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// An error that may have occurred while attempting to retrieve Coordinator
	//
	// The error contains both the kafka error code, and an error message
	// returned by the kafka broker.
	Error error
}

// FindCoordinator sends a findCoordinator request to a kafka broker and returns the
// response.
func (c *Client) FindCoordinator(ctx context.Context, req *FindCoordinatorRequest) (*FindCoordinatorResponse, error) {

	m, err := c.roundTrip(ctx, req.Addr, &findcoordinator.Request{
		Key:     req.Key,
		KeyType: int8(req.KeyType),
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).FindCoordinator: %w", err)
	}

	res := m.(*findcoordinator.Response)
	coordinator := &FindCoordinatorResponseCoordinator{
		NodeID: int(res.NodeID),
		Host:   res.Host,
		Port:   int(res.Port),
	}
	ret := &FindCoordinatorResponse{
		Throttle:    makeDuration(res.ThrottleTimeMs),
		Error:       makeError(res.ErrorCode, res.ErrorMessage),
		Coordinator: coordinator,
	}

	return ret, nil
}

// FindCoordinatorRequestV0 requests the coordinator for the specified group or transaction
//
// See http://kafka.apache.org/protocol.html#The_Messages_FindCoordinator
type findCoordinatorRequestV0 struct {
	// CoordinatorKey holds id to use for finding the coordinator (for groups, this is
	// the groupId, for transactional producers, this is the transactional id)
	CoordinatorKey string
}

func (t findCoordinatorRequestV0) size() int32 {
	return sizeofString(t.CoordinatorKey)
}

func (t findCoordinatorRequestV0) writeTo(wb *writeBuffer) {
	wb.writeString(t.CoordinatorKey)
}

type findCoordinatorResponseCoordinatorV0 struct {
	// NodeID holds the broker id.
	NodeID int32

	// Host of the broker
	Host string

	// Port on which broker accepts requests
	Port int32
}

func (t findCoordinatorResponseCoordinatorV0) size() int32 {
	return sizeofInt32(t.NodeID) +
		sizeofString(t.Host) +
		sizeofInt32(t.Port)
}

func (t findCoordinatorResponseCoordinatorV0) writeTo(wb *writeBuffer) {
	wb.writeInt32(t.NodeID)
	wb.writeString(t.Host)
	wb.writeInt32(t.Port)
}

func (t *findCoordinatorResponseCoordinatorV0) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readInt32(r, size, &t.NodeID); err != nil {
		return
	}
	if remain, err = readString(r, remain, &t.Host); err != nil {
		return
	}
	if remain, err = readInt32(r, remain, &t.Port); err != nil {
		return
	}
	return
}

type findCoordinatorResponseV0 struct {
	// ErrorCode holds response error code
	ErrorCode int16

	// Coordinator holds host and port information for the coordinator
	Coordinator findCoordinatorResponseCoordinatorV0
}

func (t findCoordinatorResponseV0) size() int32 {
	return sizeofInt16(t.ErrorCode) +
		t.Coordinator.size()
}

func (t findCoordinatorResponseV0) writeTo(wb *writeBuffer) {
	wb.writeInt16(t.ErrorCode)
	t.Coordinator.writeTo(wb)
}

func (t *findCoordinatorResponseV0) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readInt16(r, size, &t.ErrorCode); err != nil {
		return
	}
	if remain, err = (&t.Coordinator).readFrom(r, remain); err != nil {
		return
	}
	return
}
