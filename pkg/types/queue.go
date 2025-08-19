package types

import (
	log "github.com/sirupsen/logrus"
)

// Queue holds a limited size queue
type LocalQueue struct {
	Queue *Queue //capacity
}

// NewQueue create a new queue with a size of l
func NewLocalQueue(l int) *LocalQueue {
	if l == -1 {
		return &LocalQueue{
			Queue: &Queue{
				Queue: make([]Event, 0), // default capacity
				// L:     100, // default capacity
				L: int(^uint(0) >> 1), // max integer value, architecture independent
			},
		}
	}
	q := &LocalQueue{
		Queue: &Queue{
			Queue: make([]Event, l),
			L:     l,
		},
	}
	log.WithField("Capacity", q.Queue.L).Debugf("Creating queue")
	return q
}

// Add an event in the queue. If it has already l elements, the first
// element is dropped before adding the new m element
func (q *LocalQueue) Add(m Event) {
	for len(q.Queue.Queue) > q.Queue.L { //we allow to add one element more than the true capacity
		q.Queue.Queue = q.Queue.Queue[1:]
	}
	q.Queue.Queue = append(q.Queue.Queue, m)
}
func (q *LocalQueue) GetSize() int {
	return len(q.Queue.Queue)
}

// GetQueue returns the entire queue
func (q *LocalQueue) GetQueue() Queue {
	return *q.Queue
}

type QueueInterface interface {
	GetQueue() Queue
	GetSize() int
	Add(evt Event)
}

// for compatibility with
type Queue struct {
	Queue []Event
	L     int //capacity
}
