package kafka

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/segmentio/kafka-go/protocol/describegroups"
)

// DescribeGroupsRequest is a request to the DescribeGroups API.
type DescribeGroupsRequest struct {
	// Addr is the address of the kafka broker to send the request to.
	Addr net.Addr

	// GroupIDs is a slice of groups to get details for.
	GroupIDs []string
}

// DescribeGroupsResponse is a response from the DescribeGroups API.
type DescribeGroupsResponse struct {
	// Groups is a slice of details for the requested groups.
	Groups []DescribeGroupsResponseGroup
}

// DescribeGroupsResponseGroup contains the response details for a single group.
type DescribeGroupsResponseGroup struct {
	// Error is set to a non-nil value if there was an error fetching the details
	// for this group.
	Error error

	// GroupID is the ID of the group.
	GroupID string

	// GroupState is a description of the group state.
	GroupState string

	// Members contains details about each member of the group.
	Members []DescribeGroupsResponseMember
}

// MemberInfo represents the membership information for a single group member.
type DescribeGroupsResponseMember struct {
	// MemberID is the ID of the group member.
	MemberID string

	// ClientID is the ID of the client that the group member is using.
	ClientID string

	// ClientHost is the host of the client that the group member is connecting from.
	ClientHost string

	// MemberMetadata contains metadata about this group member.
	MemberMetadata DescribeGroupsResponseMemberMetadata

	// MemberAssignments contains the topic partitions that this member is assigned to.
	MemberAssignments DescribeGroupsResponseAssignments
}

// GroupMemberMetadata stores metadata associated with a group member.
type DescribeGroupsResponseMemberMetadata struct {
	// Version is the version of the metadata.
	Version int

	// Topics is the list of topics that the member is assigned to.
	Topics []string

	// UserData is the user data for the member.
	UserData []byte

	// OwnedPartitions contains the partitions owned by this group member; only set if
	// consumers are using a cooperative rebalancing assignor protocol.
	OwnedPartitions []DescribeGroupsResponseMemberMetadataOwnedPartition
}

type DescribeGroupsResponseMemberMetadataOwnedPartition struct {
	// Topic is the name of the topic.
	Topic string

	// Partitions is the partitions that are owned by the group in the topic.
	Partitions []int
}

// GroupMemberAssignmentsInfo stores the topic partition assignment data for a group member.
type DescribeGroupsResponseAssignments struct {
	// Version is the version of the assignments data.
	Version int

	// Topics contains the details of the partition assignments for each topic.
	Topics []GroupMemberTopic

	// UserData is the user data for the member.
	UserData []byte
}

// GroupMemberTopic is a mapping from a topic to a list of partitions in the topic. It is used
// to represent the topic partitions that have been assigned to a group member.
type GroupMemberTopic struct {
	// Topic is the name of the topic.
	Topic string

	// Partitions is a slice of partition IDs that this member is assigned to in the topic.
	Partitions []int
}

// DescribeGroups calls the Kafka DescribeGroups API to get information about one or more
// consumer groups. See https://kafka.apache.org/protocol#The_Messages_DescribeGroups for
// more information.
func (c *Client) DescribeGroups(
	ctx context.Context,
	req *DescribeGroupsRequest,
) (*DescribeGroupsResponse, error) {
	protoResp, err := c.roundTrip(
		ctx,
		req.Addr,
		&describegroups.Request{
			Groups: req.GroupIDs,
		},
	)
	if err != nil {
		return nil, err
	}
	apiResp := protoResp.(*describegroups.Response)
	resp := &DescribeGroupsResponse{}

	for _, apiGroup := range apiResp.Groups {
		group := DescribeGroupsResponseGroup{
			Error:      makeError(apiGroup.ErrorCode, ""),
			GroupID:    apiGroup.GroupID,
			GroupState: apiGroup.GroupState,
		}

		for _, member := range apiGroup.Members {
			decodedMetadata, err := decodeMemberMetadata(member.MemberMetadata)
			if err != nil {
				return nil, err
			}
			decodedAssignments, err := decodeMemberAssignments(member.MemberAssignment)
			if err != nil {
				return nil, err
			}

			group.Members = append(group.Members, DescribeGroupsResponseMember{
				MemberID:          member.MemberID,
				ClientID:          member.ClientID,
				ClientHost:        member.ClientHost,
				MemberAssignments: decodedAssignments,
				MemberMetadata:    decodedMetadata,
			})
		}
		resp.Groups = append(resp.Groups, group)
	}

	return resp, nil
}

// decodeMemberMetadata converts raw metadata bytes to a
// DescribeGroupsResponseMemberMetadata struct.
//
// See https://github.com/apache/kafka/blob/2.4/clients/src/main/java/org/apache/kafka/clients/consumer/internals/ConsumerProtocol.java#L49
// for protocol details.
func decodeMemberMetadata(rawMetadata []byte) (DescribeGroupsResponseMemberMetadata, error) {
	mm := DescribeGroupsResponseMemberMetadata{}

	if len(rawMetadata) == 0 {
		return mm, nil
	}

	buf := bytes.NewBuffer(rawMetadata)
	bufReader := bufio.NewReader(buf)
	remain := len(rawMetadata)

	var err error
	var version16 int16

	if remain, err = readInt16(bufReader, remain, &version16); err != nil {
		return mm, err
	}
	mm.Version = int(version16)

	if remain, err = readStringArray(bufReader, remain, &mm.Topics); err != nil {
		return mm, err
	}
	if remain, err = readBytes(bufReader, remain, &mm.UserData); err != nil {
		return mm, err
	}

	if mm.Version == 1 && remain > 0 {
		fn := func(r *bufio.Reader, size int) (fnRemain int, fnErr error) {
			op := DescribeGroupsResponseMemberMetadataOwnedPartition{}
			if fnRemain, fnErr = readString(r, size, &op.Topic); fnErr != nil {
				return
			}

			ps := []int32{}
			if fnRemain, fnErr = readInt32Array(r, fnRemain, &ps); fnErr != nil {
				return
			}

			for _, p := range ps {
				op.Partitions = append(op.Partitions, int(p))
			}

			mm.OwnedPartitions = append(mm.OwnedPartitions, op)
			return
		}

		if remain, err = readArrayWith(bufReader, remain, fn); err != nil {
			return mm, err
		}
	}

	if remain != 0 {
		return mm, fmt.Errorf("Got non-zero number of bytes remaining: %d", remain)
	}

	return mm, nil
}

// decodeMemberAssignments converts raw assignment bytes to a DescribeGroupsResponseAssignments
// struct.
//
// See https://github.com/apache/kafka/blob/2.4/clients/src/main/java/org/apache/kafka/clients/consumer/internals/ConsumerProtocol.java#L49
// for protocol details.
func decodeMemberAssignments(rawAssignments []byte) (DescribeGroupsResponseAssignments, error) {
	ma := DescribeGroupsResponseAssignments{}

	if len(rawAssignments) == 0 {
		return ma, nil
	}

	buf := bytes.NewBuffer(rawAssignments)
	bufReader := bufio.NewReader(buf)
	remain := len(rawAssignments)

	var err error
	var version16 int16

	if remain, err = readInt16(bufReader, remain, &version16); err != nil {
		return ma, err
	}
	ma.Version = int(version16)

	fn := func(r *bufio.Reader, size int) (fnRemain int, fnErr error) {
		item := GroupMemberTopic{}

		if fnRemain, fnErr = readString(r, size, &item.Topic); fnErr != nil {
			return
		}

		partitions := []int32{}

		if fnRemain, fnErr = readInt32Array(r, fnRemain, &partitions); fnErr != nil {
			return
		}
		for _, partition := range partitions {
			item.Partitions = append(item.Partitions, int(partition))
		}

		ma.Topics = append(ma.Topics, item)
		return
	}
	if remain, err = readArrayWith(bufReader, remain, fn); err != nil {
		return ma, err
	}

	if remain, err = readBytes(bufReader, remain, &ma.UserData); err != nil {
		return ma, err
	}

	if remain != 0 {
		return ma, fmt.Errorf("Got non-zero number of bytes remaining: %d", remain)
	}

	return ma, nil
}

// readInt32Array reads an array of int32s. It's adapted from the implementation of
// readStringArray.
func readInt32Array(r *bufio.Reader, sz int, v *[]int32) (remain int, err error) {
	var content []int32
	fn := func(r *bufio.Reader, size int) (fnRemain int, fnErr error) {
		var value int32
		if fnRemain, fnErr = readInt32(r, size, &value); fnErr != nil {
			return
		}
		content = append(content, value)
		return
	}
	if remain, err = readArrayWith(r, sz, fn); err != nil {
		return
	}

	*v = content
	return
}
