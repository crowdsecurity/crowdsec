package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/segmentio/kafka-go/protocol"
)

const (
	defaultCreateTopicsTimeout     = 2 * time.Second
	defaultDeleteTopicsTimeout     = 2 * time.Second
	defaultCreatePartitionsTimeout = 2 * time.Second
	defaultProduceTimeout          = 500 * time.Millisecond
	defaultMaxWait                 = 500 * time.Millisecond
)

// Client is a high-level API to interract with kafka brokers.
//
// All methods of the Client type accept a context as first argument, which may
// be used to asynchronously cancel the requests.
//
// Clients are safe to use concurrently from multiple goroutines, as long as
// their configuration is not changed after first use.
type Client struct {
	// Address of the kafka cluster (or specific broker) that the client will be
	// sending requests to.
	//
	// This field is optional, the address may be provided in each request
	// instead. The request address takes precedence if both were specified.
	Addr net.Addr

	// Time limit for requests sent by this client.
	//
	// If zero, no timeout is applied.
	Timeout time.Duration

	// A transport used to communicate with the kafka brokers.
	//
	// If nil, DefaultTransport is used.
	Transport RoundTripper
}

// A ConsumerGroup and Topic as these are both strings we define a type for
// clarity when passing to the Client as a function argument
//
// N.B TopicAndGroup is currently experimental! Therefore, it is subject to
// change, including breaking changes between MINOR and PATCH releases.
//
// DEPRECATED: this type will be removed in version 1.0, programs should
// migrate to use kafka.(*Client).OffsetFetch instead.
type TopicAndGroup struct {
	Topic   string
	GroupId string
}

// ConsumerOffsets returns a map[int]int64 of partition to committed offset for
// a consumer group id and topic.
//
// DEPRECATED: this method will be removed in version 1.0, programs should
// migrate to use kafka.(*Client).OffsetFetch instead.
func (c *Client) ConsumerOffsets(ctx context.Context, tg TopicAndGroup) (map[int]int64, error) {
	metadata, err := c.Metadata(ctx, &MetadataRequest{
		Topics: []string{tg.Topic},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get topic metadata :%w", err)
	}

	topic := metadata.Topics[0]
	partitions := make([]int, len(topic.Partitions))

	for i := range topic.Partitions {
		partitions[i] = topic.Partitions[i].ID
	}

	offsets, err := c.OffsetFetch(ctx, &OffsetFetchRequest{
		GroupID: tg.GroupId,
		Topics: map[string][]int{
			tg.Topic: partitions,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get offsets: %w", err)
	}

	topicOffsets := offsets.Topics[topic.Name]
	partitionOffsets := make(map[int]int64, len(topicOffsets))

	for _, off := range topicOffsets {
		partitionOffsets[off.Partition] = off.CommittedOffset
	}

	return partitionOffsets, nil
}

func (c *Client) roundTrip(ctx context.Context, addr net.Addr, msg protocol.Message) (protocol.Message, error) {
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}

	if addr == nil {
		if addr = c.Addr; addr == nil {
			return nil, errors.New("no address was given for the kafka cluster in the request or on the client")
		}
	}

	return c.transport().RoundTrip(ctx, addr, msg)
}

func (c *Client) transport() RoundTripper {
	if c.Transport != nil {
		return c.Transport
	}
	return DefaultTransport
}

func (c *Client) timeout(ctx context.Context, defaultTimeout time.Duration) time.Duration {
	timeout := c.Timeout

	if deadline, ok := ctx.Deadline(); ok {
		if remain := time.Until(deadline); remain < timeout {
			timeout = remain
		}
	}

	if timeout > 0 {
		// Half the timeout because it is communicated to kafka in multiple
		// requests (e.g. Fetch, Produce, etc...), this adds buffer to account
		// for network latency when waiting for the response from kafka.
		return timeout / 2
	}

	return defaultTimeout
}

func (c *Client) timeoutMs(ctx context.Context, defaultTimeout time.Duration) int32 {
	return milliseconds(c.timeout(ctx, defaultTimeout))
}
