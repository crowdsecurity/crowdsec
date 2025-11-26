package tracker

import (
	"maps"
	"sync"
)

// Tracker is a concurrency-safe map wrapper for tracking live objects like
// containers or services.
//
// It uses a sync.RWMutex to guard access to its internal map.
// The zero value of tracker is ready to use; calling Set() will lazily initialize
// the internal map if needed.
//
// The type parameter T can be either a value type (e.g. int, struct) or a pointer
// type (e.g. *ContainerConfig). Use pointers if T contains fields that should not
// be copied (for example tombs, mutexes, or loggers).
type Tracker[T any] struct {
	mu    sync.RWMutex
	items map[string]T
}

// NewTracker creates and initializes a new tracker for type T.
//
// While the zero value of Tracker is ready to use, using the constructor is
// recommended in case future versions require explicit initialization.
func NewTracker[T any]() *Tracker[T] {
	return &Tracker[T]{items: make(map[string]T)}
}

// GetAll returns a snapshot copy of all items currently in the tracker.
//
// The returned map is a shallow copy: modifying it will not affect
// the underlying tracker contents. Safe for concurrent use.
func (t *Tracker[T]) GetAll() map[string]T {
	t.mu.RLock()
	snapshot := make(map[string]T, len(t.items))
	maps.Copy(snapshot, t.items)
	t.mu.RUnlock()
	return snapshot
}

// Get returns the item stored under the given id, along with a boolean
// indicating whether it was found.
func (t *Tracker[T]) Get(id string) (T, bool) {
	t.mu.RLock()
	v, ok := t.items[id]
	t.mu.RUnlock()
	return v, ok
}

// Set stores item under the given id. If the tracker map is nil,
// it will lazily initialize it.
func (t *Tracker[T]) Set(id string, item T) {
	t.mu.Lock()
	if t.items == nil {
		t.items = make(map[string]T)
	}
	t.items[id] = item
	t.mu.Unlock()
}

// Delete removes the item with the given id, if present.
func (t *Tracker[T]) Delete(id string) {
	t.mu.Lock()
	delete(t.items, id)
	t.mu.Unlock()
}

// Clear removes all tracked items and returns a snapshot of the previous contents.
//
// The returned map is a shallow copy of the internal state at the time of the call,
// so further modifications to it do not affect the tracker.
func (t *Tracker[T]) Clear() map[string]T {
	t.mu.Lock()
	old := make(map[string]T, len(t.items))
	maps.Copy(old, t.items)
	t.items = make(map[string]T)
	t.mu.Unlock()
	return old
}

// Len returns the number of items currently stored in the tracker.
func (t *Tracker[T]) Len() int {
	t.mu.RLock()
	n := len(t.items)
	t.mu.RUnlock()
	return n
}
