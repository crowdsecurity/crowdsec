package kafka

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/leavegroup"
)

// LeaveGroupRequest is the request structure for the LeaveGroup function.
type LeaveGroupRequest struct {
	// Address of the kafka broker to sent he request to.
	Addr net.Addr

	// GroupID of the group to leave.
	GroupID string

	// List of leaving member identities.
	Members []LeaveGroupRequestMember
}

// LeaveGroupRequestMember represents the indentify of a member leaving a group.
type LeaveGroupRequestMember struct {
	// The member ID to remove from the group.
	ID string

	// The group instance ID to remove from the group.
	GroupInstanceID string
}

// LeaveGroupResponse is the response structure for the LeaveGroup function.
type LeaveGroupResponse struct {
	// An error that may have occurred when attempting to leave the group.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Error error

	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// List of leaving member responses.
	Members []LeaveGroupResponseMember
}

// LeaveGroupResponseMember represents a member leaving the group.
type LeaveGroupResponseMember struct {
	// The member ID of the member leaving the group.
	ID string

	// The group instance ID to remove from the group.
	GroupInstanceID string

	// An error that may have occured when attempting to remove the member from the group.
	//
	// The errors contain the kafka error code. Programs may use the standard
	// errors.Is function to test the error against kafka error codes.
	Error error
}

func (c *Client) LeaveGroup(ctx context.Context, req *LeaveGroupRequest) (*LeaveGroupResponse, error) {
	leaveGroup := leavegroup.Request{
		GroupID: req.GroupID,
		Members: make([]leavegroup.RequestMember, 0, len(req.Members)),
	}

	for _, member := range req.Members {
		leaveGroup.Members = append(leaveGroup.Members, leavegroup.RequestMember{
			MemberID:        member.ID,
			GroupInstanceID: member.GroupInstanceID,
		})
	}

	m, err := c.roundTrip(ctx, req.Addr, &leaveGroup)
	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).LeaveGroup: %w", err)
	}

	r := m.(*leavegroup.Response)

	res := &LeaveGroupResponse{
		Error:    makeError(r.ErrorCode, ""),
		Throttle: makeDuration(r.ThrottleTimeMS),
	}

	if len(r.Members) == 0 {
		// If we're using a version of the api without the
		// members array in the response, just add a member
		// so the api is consistent across versions.
		r.Members = []leavegroup.ResponseMember{
			{
				MemberID:        req.Members[0].ID,
				GroupInstanceID: req.Members[0].GroupInstanceID,
			},
		}
	}

	res.Members = make([]LeaveGroupResponseMember, 0, len(r.Members))
	for _, member := range r.Members {
		res.Members = append(res.Members, LeaveGroupResponseMember{
			ID:              member.MemberID,
			GroupInstanceID: member.GroupInstanceID,
			Error:           makeError(member.ErrorCode, ""),
		})
	}

	return res, nil
}

type leaveGroupRequestV0 struct {
	// GroupID holds the unique group identifier
	GroupID string

	// MemberID assigned by the group coordinator or the zero string if joining
	// for the first time.
	MemberID string
}

func (t leaveGroupRequestV0) size() int32 {
	return sizeofString(t.GroupID) + sizeofString(t.MemberID)
}

func (t leaveGroupRequestV0) writeTo(wb *writeBuffer) {
	wb.writeString(t.GroupID)
	wb.writeString(t.MemberID)
}

type leaveGroupResponseV0 struct {
	// ErrorCode holds response error code
	ErrorCode int16
}

func (t leaveGroupResponseV0) size() int32 {
	return sizeofInt16(t.ErrorCode)
}

func (t leaveGroupResponseV0) writeTo(wb *writeBuffer) {
	wb.writeInt16(t.ErrorCode)
}

func (t *leaveGroupResponseV0) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	remain, err = readInt16(r, size, &t.ErrorCode)
	return
}
