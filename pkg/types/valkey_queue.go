package types

import (
	"context"
	"encoding/json"

	valkey "github.com/valkey-io/valkey-go"
)

type RedisQueue struct {
	client *valkey.Client
	ctx    context.Context
	limit  int
}

func NewRedisQueue(addr string, limit int) *RedisQueue {
	client, err := valkey.NewClient(&valkey.Options{
		Addr: addr,
	})

	return &RedisQueue{
		client: client,
		ctx:    context.Background(),
		limit:  limit,
	}
}

// Add an event to the queue for a given stackKey
func (r *RedisQueue) Add(stackKey string, evt Event) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}

	_ = r.client.RPush(r.ctx, stackKey, data).Err()

	if r.limit > 0 {
		_ = r.client.LTrim(r.ctx, stackKey, -r.limit, -1).Err()
	}
}

// Get all events from the queue for a given stackKey
func (r *RedisQueue) GetQueue(stackKey string) Queue {
	list, err := r.client.LRange(r.ctx, stackKey, 0, -1).Result()
	q := Queue{L: r.limit}
	for _, item := range list {
		var evt Event
		if err := json.Unmarshal([]byte(item), &evt); err == nil {
			q.Queue = append(q.Queue, evt)
		}
	}
	return q
}

// Get current size of the queue for a given stackKey
func (r *RedisQueue) GetSize(stackKey string) int {
	size, err := r.client.LLen(r.ctx, stackKey).Result()
	if err != nil {
		return 0
	}
	return int(size)
}
