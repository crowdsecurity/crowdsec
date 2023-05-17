package kafka

import (
	"bufio"
	"context"
	"net"

	"github.com/segmentio/kafka-go/protocol/listgroups"
)

// ListGroupsRequest is a request to the ListGroups API.
type ListGroupsRequest struct {
	// Addr is the address of the kafka broker to send the request to.
	Addr net.Addr
}

// ListGroupsResponse is a response from the ListGroups API.
type ListGroupsResponse struct {
	// Error is set to a non-nil value if a top-level error occurred while fetching
	// groups.
	Error error

	// Groups contains the list of groups.
	Groups []ListGroupsResponseGroup
}

// ListGroupsResponseGroup contains the response details for a single group.
type ListGroupsResponseGroup struct {
	// GroupID is the ID of the group.
	GroupID string

	// Coordinator is the ID of the coordinator broker for the group.
	Coordinator int
}

func (c *Client) ListGroups(
	ctx context.Context,
	req *ListGroupsRequest,
) (*ListGroupsResponse, error) {
	protoResp, err := c.roundTrip(ctx, req.Addr, &listgroups.Request{})
	if err != nil {
		return nil, err
	}
	apiResp := protoResp.(*listgroups.Response)
	resp := &ListGroupsResponse{
		Error: makeError(apiResp.ErrorCode, ""),
	}

	for _, apiGroupInfo := range apiResp.Groups {
		resp.Groups = append(resp.Groups, ListGroupsResponseGroup{
			GroupID:     apiGroupInfo.GroupID,
			Coordinator: int(apiGroupInfo.BrokerID),
		})
	}

	return resp, nil
}

// TODO: Remove everything below and use protocol-based version above everywhere.
type listGroupsRequestV1 struct {
}

func (t listGroupsRequestV1) size() int32 {
	return 0
}

func (t listGroupsRequestV1) writeTo(wb *writeBuffer) {
}

type listGroupsResponseGroupV1 struct {
	// GroupID holds the unique group identifier
	GroupID      string
	ProtocolType string
}

func (t listGroupsResponseGroupV1) size() int32 {
	return sizeofString(t.GroupID) + sizeofString(t.ProtocolType)
}

func (t listGroupsResponseGroupV1) writeTo(wb *writeBuffer) {
	wb.writeString(t.GroupID)
	wb.writeString(t.ProtocolType)
}

func (t *listGroupsResponseGroupV1) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readString(r, size, &t.GroupID); err != nil {
		return
	}
	if remain, err = readString(r, remain, &t.ProtocolType); err != nil {
		return
	}
	return
}

type listGroupsResponseV1 struct {
	// ThrottleTimeMS holds the duration in milliseconds for which the request
	// was throttled due to quota violation (Zero if the request did not violate
	// any quota)
	ThrottleTimeMS int32

	// ErrorCode holds response error code
	ErrorCode int16
	Groups    []listGroupsResponseGroupV1
}

func (t listGroupsResponseV1) size() int32 {
	return sizeofInt32(t.ThrottleTimeMS) +
		sizeofInt16(t.ErrorCode) +
		sizeofArray(len(t.Groups), func(i int) int32 { return t.Groups[i].size() })
}

func (t listGroupsResponseV1) writeTo(wb *writeBuffer) {
	wb.writeInt32(t.ThrottleTimeMS)
	wb.writeInt16(t.ErrorCode)
	wb.writeArray(len(t.Groups), func(i int) { t.Groups[i].writeTo(wb) })
}

func (t *listGroupsResponseV1) readFrom(r *bufio.Reader, size int) (remain int, err error) {
	if remain, err = readInt32(r, size, &t.ThrottleTimeMS); err != nil {
		return
	}
	if remain, err = readInt16(r, remain, &t.ErrorCode); err != nil {
		return
	}

	fn := func(withReader *bufio.Reader, withSize int) (fnRemain int, fnErr error) {
		var item listGroupsResponseGroupV1
		if fnRemain, fnErr = (&item).readFrom(withReader, withSize); err != nil {
			return
		}
		t.Groups = append(t.Groups, item)
		return
	}
	if remain, err = readArrayWith(r, remain, fn); err != nil {
		return
	}

	return
}
