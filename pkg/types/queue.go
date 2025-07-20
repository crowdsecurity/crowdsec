package types

import (
	log "github.com/sirupsen/logrus"
)

// Queue holds a limited size queue
type LocalQueue struct {
	Queue []Event
	L     int //capacity
}

// NewQueue create a new queue with a size of l
func NewLocalQueue(l int) *LocalQueue {
	if l == -1 {
		return &LocalQueue{
			Queue: make([]Event, 0),
			L:     int(^uint(0) >> 1), // max integer value, architecture independent
		}
	}
	q := &LocalQueue{
		Queue: make([]Event, 0, l),
		L:     l,
	}
	log.WithField("Capacity", q.L).Debugf("Creating queue")
	return q
}

// Add an event in the queue. If it has already l elements, the first
// element is dropped before adding the new m element
func (q *LocalQueue) Add(m Event) {
	for len(q.Queue) > q.L { //we allow to add one element more than the true capacity
		q.Queue = q.Queue[1:]
	}
	q.Queue = append(q.Queue, m)
}
func (q *LocalQueue) GetSize() int {
	return len(q.Queue)
}

// GetQueue returns the entire queue
func (q *LocalQueue) GetQueue() []Event {
	return q.Queue
}

type Queue interface {
	GetQueue() []Event
	GetSize() int
	Add(Event)
}

func NewQueue(l int) Queue {
	return NewLocalQueue(l)
}
