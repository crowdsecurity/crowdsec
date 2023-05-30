package kafka

import (
	"context"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol/alterpartitionreassignments"
)

// AlterPartitionReassignmentsRequest is a request to the AlterPartitionReassignments API.
type AlterPartitionReassignmentsRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// Topic is the name of the topic to alter partitions in.
	Topic string

	// Assignments is the list of partition reassignments to submit to the API.
	Assignments []AlterPartitionReassignmentsRequestAssignment

	// Timeout is the amount of time to wait for the request to complete.
	Timeout time.Duration
}

// AlterPartitionReassignmentsRequestAssignment contains the requested reassignments for a single
// partition.
type AlterPartitionReassignmentsRequestAssignment struct {
	// PartitionID is the ID of the partition to make the reassignments in.
	PartitionID int

	// BrokerIDs is a slice of brokers to set the partition replicas to.
	BrokerIDs []int
}

// AlterPartitionReassignmentsResponse is a response from the AlterPartitionReassignments API.
type AlterPartitionReassignmentsResponse struct {
	// Error is set to a non-nil value including the code and message if a top-level
	// error was encountered when doing the update.
	Error error

	// PartitionResults contains the specific results for each partition.
	PartitionResults []AlterPartitionReassignmentsResponsePartitionResult
}

// AlterPartitionReassignmentsResponsePartitionResult contains the detailed result of
// doing reassignments for a single partition.
type AlterPartitionReassignmentsResponsePartitionResult struct {
	// PartitionID is the ID of the partition that was altered.
	PartitionID int

	// Error is set to a non-nil value including the code and message if an error was encountered
	// during the update for this partition.
	Error error
}

func (c *Client) AlterPartitionReassignments(
	ctx context.Context,
	req *AlterPartitionReassignmentsRequest,
) (*AlterPartitionReassignmentsResponse, error) {
	apiPartitions := []alterpartitionreassignments.RequestPartition{}

	for _, assignment := range req.Assignments {
		replicas := []int32{}
		for _, brokerID := range assignment.BrokerIDs {
			replicas = append(replicas, int32(brokerID))
		}

		apiPartitions = append(
			apiPartitions,
			alterpartitionreassignments.RequestPartition{
				PartitionIndex: int32(assignment.PartitionID),
				Replicas:       replicas,
			},
		)
	}

	apiReq := &alterpartitionreassignments.Request{
		TimeoutMs: int32(req.Timeout.Milliseconds()),
		Topics: []alterpartitionreassignments.RequestTopic{
			{
				Name:       req.Topic,
				Partitions: apiPartitions,
			},
		},
	}

	protoResp, err := c.roundTrip(
		ctx,
		req.Addr,
		apiReq,
	)
	if err != nil {
		return nil, err
	}
	apiResp := protoResp.(*alterpartitionreassignments.Response)

	resp := &AlterPartitionReassignmentsResponse{
		Error: makeError(apiResp.ErrorCode, apiResp.ErrorMessage),
	}

	for _, topicResult := range apiResp.Results {
		for _, partitionResult := range topicResult.Partitions {
			resp.PartitionResults = append(
				resp.PartitionResults,
				AlterPartitionReassignmentsResponsePartitionResult{
					PartitionID: int(partitionResult.PartitionIndex),
					Error:       makeError(partitionResult.ErrorCode, partitionResult.ErrorMessage),
				},
			)
		}
	}

	return resp, nil
}
