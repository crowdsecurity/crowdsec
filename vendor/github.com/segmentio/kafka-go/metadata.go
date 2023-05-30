package kafka

import (
	"context"
	"fmt"
	"net"
	"time"

	metadataAPI "github.com/segmentio/kafka-go/protocol/metadata"
)

// MetadataRequest represents a request sent to a kafka broker to retrieve its
// cluster metadata.
type MetadataRequest struct {
	// Address of the kafka broker to send the request to.
	Addr net.Addr

	// The list of topics to retrieve metadata for.
	Topics []string
}

// MetadatResponse represents a response from a kafka broker to a metadata
// request.
type MetadataResponse struct {
	// The amount of time that the broker throttled the request.
	Throttle time.Duration

	// Name of the kafka cluster that client retrieved metadata from.
	ClusterID string

	// The broker which is currently the controller for the cluster.
	Controller Broker

	// The list of brokers registered to the cluster.
	Brokers []Broker

	// The list of topics available on the cluster.
	Topics []Topic
}

// Metadata sends a metadata request to a kafka broker and returns the response.
func (c *Client) Metadata(ctx context.Context, req *MetadataRequest) (*MetadataResponse, error) {
	m, err := c.roundTrip(ctx, req.Addr, &metadataAPI.Request{
		TopicNames: req.Topics,
	})

	if err != nil {
		return nil, fmt.Errorf("kafka.(*Client).Metadata: %w", err)
	}

	res := m.(*metadataAPI.Response)
	ret := &MetadataResponse{
		Throttle:  makeDuration(res.ThrottleTimeMs),
		Brokers:   make([]Broker, len(res.Brokers)),
		Topics:    make([]Topic, len(res.Topics)),
		ClusterID: res.ClusterID,
	}

	brokers := make(map[int32]Broker, len(res.Brokers))

	for i, b := range res.Brokers {
		broker := Broker{
			Host: b.Host,
			Port: int(b.Port),
			ID:   int(b.NodeID),
			Rack: b.Rack,
		}

		ret.Brokers[i] = broker
		brokers[b.NodeID] = broker

		if b.NodeID == res.ControllerID {
			ret.Controller = broker
		}
	}

	for i, t := range res.Topics {
		ret.Topics[i] = Topic{
			Name:       t.Name,
			Internal:   t.IsInternal,
			Partitions: make([]Partition, len(t.Partitions)),
			Error:      makeError(t.ErrorCode, ""),
		}

		for j, p := range t.Partitions {
			partition := Partition{
				Topic:    t.Name,
				ID:       int(p.PartitionIndex),
				Leader:   brokers[p.LeaderID],
				Replicas: make([]Broker, len(p.ReplicaNodes)),
				Isr:      make([]Broker, len(p.IsrNodes)),
				Error:    makeError(p.ErrorCode, ""),
			}

			for i, id := range p.ReplicaNodes {
				partition.Replicas[i] = brokers[id]
			}

			for i, id := range p.IsrNodes {
				partition.Isr[i] = brokers[id]
			}

			ret.Topics[i].Partitions[j] = partition
		}
	}

	return ret, nil
}

type topicMetadataRequestV1 []string

func (r topicMetadataRequestV1) size() int32 {
	return sizeofStringArray([]string(r))
}

func (r topicMetadataRequestV1) writeTo(wb *writeBuffer) {
	// communicate nil-ness to the broker by passing -1 as the array length.
	// for this particular request, the broker interpets a zero length array
	// as a request for no topics whereas a nil array is for all topics.
	if r == nil {
		wb.writeArrayLen(-1)
	} else {
		wb.writeStringArray([]string(r))
	}
}

type metadataResponseV1 struct {
	Brokers      []brokerMetadataV1
	ControllerID int32
	Topics       []topicMetadataV1
}

func (r metadataResponseV1) size() int32 {
	n1 := sizeofArray(len(r.Brokers), func(i int) int32 { return r.Brokers[i].size() })
	n2 := sizeofArray(len(r.Topics), func(i int) int32 { return r.Topics[i].size() })
	return 4 + n1 + n2
}

func (r metadataResponseV1) writeTo(wb *writeBuffer) {
	wb.writeArray(len(r.Brokers), func(i int) { r.Brokers[i].writeTo(wb) })
	wb.writeInt32(r.ControllerID)
	wb.writeArray(len(r.Topics), func(i int) { r.Topics[i].writeTo(wb) })
}

type brokerMetadataV1 struct {
	NodeID int32
	Host   string
	Port   int32
	Rack   string
}

func (b brokerMetadataV1) size() int32 {
	return 4 + 4 + sizeofString(b.Host) + sizeofString(b.Rack)
}

func (b brokerMetadataV1) writeTo(wb *writeBuffer) {
	wb.writeInt32(b.NodeID)
	wb.writeString(b.Host)
	wb.writeInt32(b.Port)
	wb.writeString(b.Rack)
}

type topicMetadataV1 struct {
	TopicErrorCode int16
	TopicName      string
	Internal       bool
	Partitions     []partitionMetadataV1
}

func (t topicMetadataV1) size() int32 {
	return 2 + 1 +
		sizeofString(t.TopicName) +
		sizeofArray(len(t.Partitions), func(i int) int32 { return t.Partitions[i].size() })
}

func (t topicMetadataV1) writeTo(wb *writeBuffer) {
	wb.writeInt16(t.TopicErrorCode)
	wb.writeString(t.TopicName)
	wb.writeBool(t.Internal)
	wb.writeArray(len(t.Partitions), func(i int) { t.Partitions[i].writeTo(wb) })
}

type partitionMetadataV1 struct {
	PartitionErrorCode int16
	PartitionID        int32
	Leader             int32
	Replicas           []int32
	Isr                []int32
}

func (p partitionMetadataV1) size() int32 {
	return 2 + 4 + 4 + sizeofInt32Array(p.Replicas) + sizeofInt32Array(p.Isr)
}

func (p partitionMetadataV1) writeTo(wb *writeBuffer) {
	wb.writeInt16(p.PartitionErrorCode)
	wb.writeInt32(p.PartitionID)
	wb.writeInt32(p.Leader)
	wb.writeInt32Array(p.Replicas)
	wb.writeInt32Array(p.Isr)
}
