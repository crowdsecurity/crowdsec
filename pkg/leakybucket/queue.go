package leakybucket

import (
	"reflect"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

//A very simple queue mechanism to hold track of the objects in the bucket

// Queue is a simple struct that holds a limited size queue
type Queue struct {
	Queue []types.Event
	L     int //capacity
}

// NewQueue create a new queue with a size of l
func NewQueue(l int) *Queue {
	if l == -1 {
		return &Queue{
			Queue: make([]types.Event, 0),
			L:     int(^uint(0) >> 1), // max integer value, architecture independent
		}
	}
	q := &Queue{
		Queue: make([]types.Event, 0, l),
		L:     l,
	}
	log.WithFields(log.Fields{"Capacity": q.L}).Debugf("Creating queue")
	return q
}

// Add an event in the queue. If it has already l elements, the first
// element is dropped before adding the new m element
func (q *Queue) Add(m types.Event) {
	for len(q.Queue) > q.L { //we allow to add one element more than the true capacity
		q.Queue = q.Queue[1:]
	}
	q.Queue = append(q.Queue, m)
}

//Remove removes and return the last element of the queue
func (q *Queue) Remove() *types.Event {
	if len(q.Queue) > 0 {
		var dropped types.Event = q.Queue[0]
		q.Queue = q.Queue[1:]
		return &dropped
	}
	return nil
}

// GetQueue returns the entire queue
func (q *Queue) GetQueue() []types.Event {
	return q.Queue
}

// In test if evt is in the queue
func (q *Queue) In(evt types.Event) bool {
	for _, element := range q.Queue {
		if reflect.DeepEqual(element, evt) {
			return true
		}
	}
	return false
}

// Len gives de the Len of queue
func (q *Queue) Len() int {
	return len(q.Queue)
}

// Size gives de the Size of queue
func (q *Queue) Size() int {
	return q.L
}
