package types

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/valkey-io/valkey-go"
)

// ValkeyQueueConfig holds configuration for Valkey-based queue
type ValkeyQueueConfig struct {
	ClientOption valkey.ClientOption `yaml:"client_option"`
	KeyPrefix    string              `yaml:"key_prefix"`
}

// ValkeyQueue implements the QueueInterface using Valkey as backend
type ValkeyQueue struct {
	client    valkey.Client
	keyPrefix string
	bucketID  string
	capacity  int // Maximum queue length (L in LocalQueue)
	ctx       context.Context
}

// NewValkeyQueue creates a new Valkey-based queue implementation
func NewValkeyQueue(config ValkeyQueueConfig, bucketID string, capacity int) *ValkeyQueue {
	client, err := valkey.NewClient(config.ClientOption)
	if err != nil {
		log.Errorf("failed to create Valkey client: %w", err)
		return nil
	}

	ctx := context.Background()

	// Test connection with a simple ping
	if err := client.Do(ctx, client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		log.Errorf("failed to connect to Valkey: %w", err)
		return nil
	}

	keyPrefix := config.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "crowdsec:queue"
	}

	// Handle capacity like LocalQueue does
	if capacity == -1 {
		capacity = int(^uint(0) >> 1) // max integer value, architecture independent
	}

	return &ValkeyQueue{
		client:    client,
		keyPrefix: keyPrefix,
		bucketID:  bucketID,
		capacity:  capacity,
		ctx:       ctx,
	}
}

// getQueueKey returns the Valkey key for this bucket's queue
func (vq *ValkeyQueue) getQueueKey() string {
	return fmt.Sprintf("%s:%s", vq.keyPrefix, vq.bucketID)
}

// Add adds an event to the queue (implements QueueInterface)
// Mimics LocalQueue behavior: if queue exceeds capacity, removes old events
func (vq *ValkeyQueue) Add(event Event) {
	data, err := json.Marshal(event)
	if err != nil {
		// Log error but don't return it to match the interface
		fmt.Printf("failed to marshal event: %v\n", err)
		return
	}

	// Add the new event first
	cmd := vq.client.B().Rpush().Key(vq.getQueueKey()).Element(string(data)).Build()
	if err := vq.client.Do(vq.ctx, cmd).Error(); err != nil {
		fmt.Printf("failed to push event to Valkey queue: %v\n", err)
		return
	}

	// Check and enforce capacity limit like LocalQueue does:
	// "we allow to add one element more than the true capacity"
	for vq.GetSize() > vq.capacity {
		// Remove from the left (oldest events)
		popCmd := vq.client.B().Lpop().Key(vq.getQueueKey()).Build()
		vq.client.Do(vq.ctx, popCmd)
	}
}

// GetQueue returns the entire queue (implements QueueInterface)
func (vq *ValkeyQueue) GetQueue() Queue {
	cmd := vq.client.B().Lrange().Key(vq.getQueueKey()).Start(0).Stop(-1).Build()
	result := vq.client.Do(vq.ctx, cmd)

	items, err := result.AsStrSlice()
	if err != nil {
		return Queue{
			Queue: []Event{},
			L:     vq.capacity, // Return the configured capacity, not 0
		}
	}

	events := make([]Event, 0, len(items))
	for _, item := range items {
		var event Event
		if err := json.Unmarshal([]byte(item), &event); err != nil {
			continue // Skip malformed events
		}
		events = append(events, event)
	}

	return Queue{
		Queue: events,
		L:     vq.capacity, // L represents capacity, not current length
	}
}

// GetSize returns the current length of the queue (implements QueueInterface)
func (vq *ValkeyQueue) GetSize() int {
	cmd := vq.client.B().Llen().Key(vq.getQueueKey()).Build()
	result := vq.client.Do(vq.ctx, cmd)

	length, err := result.AsInt64()
	if err != nil {
		return 0
	}
	return int(length)
}

// Clear removes all events from the queue (implements Queue interface)
func (vq *ValkeyQueue) Clear() error {
	cmd := vq.client.B().Del().Key(vq.getQueueKey()).Build()
	if err := vq.client.Do(vq.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to clear Valkey queue: %w", err)
	}
	return nil
}

// Close closes the Valkey connection
func (vq *ValkeyQueue) Close() error {
	vq.client.Close()
	return nil
}

// Additional methods that extend the basic Queue interface

// Pop removes and returns the oldest event from the queue (FIFO)
func (vq *ValkeyQueue) Pop() (Event, error) {
	var event Event

	cmd := vq.client.B().Lpop().Key(vq.getQueueKey()).Build()
	result := vq.client.Do(vq.ctx, cmd)

	item, err := result.ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return event, fmt.Errorf("queue is empty")
		}
		return event, fmt.Errorf("failed to pop from Valkey queue: %w", err)
	}

	if err := json.Unmarshal([]byte(item), &event); err != nil {
		return event, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return event, nil
}

// SetTTL sets a TTL for the entire queue
func (vq *ValkeyQueue) SetTTL(duration time.Duration) error {
	cmd := vq.client.B().Expire().Key(vq.getQueueKey()).Seconds(int64(duration.Seconds())).Build()
	if err := vq.client.Do(vq.ctx, cmd).Error(); err != nil {
		return fmt.Errorf("failed to set TTL on Valkey queue: %w", err)
	}
	return nil
}

// GetOldestEvent returns the oldest event without removing it
func (vq *ValkeyQueue) GetOldestEvent() (Event, error) {
	var event Event

	cmd := vq.client.B().Lindex().Key(vq.getQueueKey()).Index(0).Build()
	result := vq.client.Do(vq.ctx, cmd)

	item, err := result.ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return event, fmt.Errorf("queue is empty")
		}
		return event, fmt.Errorf("failed to get oldest event: %w", err)
	}

	if err := json.Unmarshal([]byte(item), &event); err != nil {
		return event, fmt.Errorf("failed to unmarshal event: %w", err)
	}

	return event, nil
}

// Cleanup removes events older than the specified duration
func (vq *ValkeyQueue) Cleanup(maxAge time.Duration) error {
	cutoffTime := time.Now().Add(-maxAge)

	for {
		event, err := vq.GetOldestEvent()
		if err != nil {
			break // No more items or error
		}

		if event.Time.Before(cutoffTime) {
			// Remove expired item
			cmd := vq.client.B().Lpop().Key(vq.getQueueKey()).Build()
			vq.client.Do(vq.ctx, cmd)
		} else {
			// Items are ordered by time, so we can stop here
			break
		}
	}

	return nil
}

// Factory integration

// QueueType represents the type of queue implementation
type QueueType string

const (
	QueueTypeLocal  QueueType = "local"
	QueueTypeValkey QueueType = "valkey"
)

// QueueConfig holds configuration for any queue type
type QueueConfig struct {
	Type   QueueType          `yaml:"type"`
	Valkey *ValkeyQueueConfig `yaml:"valkey,omitempty"`
}

// CreateQueue creates a queue based on type - hardcoded for benchmarking
func CreateQueue(bucketID string, capacity int) QueueInterface {
	queueType := "valkey"
	switch queueType {
	case "valkey":
		// Hardcoded localhost Valkey for benchmarking
		config := ValkeyQueueConfig{
			ClientOption: valkey.ClientOption{
				InitAddress: []string{"localhost:6379"},
				SelectDB:    0,
			},
			KeyPrefix: "crowdsec:benchmark",
		}
		return NewValkeyQueue(config, bucketID, capacity)
	case "local":
		// Return the existing LocalQueue implementation
		return NewLocalQueue(capacity)
	default:
		return nil
	}
}

// Example usage for benchmarking:
/*
// Create Valkey queue for benchmarking
valkeyQueue, err := CreateQueue("valkey", "benchmark-bucket", 1000)
if err != nil {
    log.Fatal(err)
}

// Create local queue for comparison
localQueue, err := CreateQueue("local", "benchmark-bucket", 1000)
if err != nil {
    log.Fatal(err)
}

// Now benchmark both implementations...
*/
