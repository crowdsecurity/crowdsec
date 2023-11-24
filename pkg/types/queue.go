package types

import (
	log "github.com/sirupsen/logrus"
)

// Queue holds a limited size queue
type Queue struct {
	Queue []Event
	L     int //capacity
}

// NewQueue create a new queue with a size of l
func NewQueue(l int) *Queue {
	if l == -1 {
		return &Queue{
			Queue: make([]Event, 0),
			L:     int(^uint(0) >> 1), // max integer value, architecture independent
		}
	}
	q := &Queue{
		Queue: make([]Event, 0, l),
		L:     l,
	}
	log.WithFields(log.Fields{"Capacity": q.L}).Debugf("Creating queue")
	return q
}

// Add an event in the queue. If it has already l elements, the first
// element is dropped before adding the new m element
func (q *Queue) Add(m Event) {
	for len(q.Queue) > q.L { //we allow to add one element more than the true capacity
		q.Queue = q.Queue[1:]
	}
	q.Queue = append(q.Queue, m)
}

// GetQueue returns the entire queue
func (q *Queue) GetQueue() []Event {
	return q.Queue
}
