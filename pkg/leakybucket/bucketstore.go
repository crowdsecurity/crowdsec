package leakybucket

import (
	"maps"
	"sync"
)

// BucketStore is the struct used to hold buckets during the lifecycle of the app
// (i.e. between reloads).
type BucketStore struct {
	mu sync.Mutex        // lock to mutate m
	m map[string]*Leaky
	muFlow sync.RWMutex // read lock for pours, write lock for dump/snapshot/GC
}

func NewBucketStore() *BucketStore {
	return &BucketStore{
		m:           make(map[string]*Leaky),
	}
}

func (b *BucketStore) Load(key string) (*Leaky, bool) {
	b.mu.Lock()
	v, ok := b.m[key]
	b.mu.Unlock()
	if !ok {
		return nil, false
	}
	return v, true
}

func (b *BucketStore) LoadOrStore(key string, val *Leaky) (*Leaky, bool) {
	b.mu.Lock()
	if existing, ok := b.m[key]; ok {
		b.mu.Unlock()
		return existing, true
	}
	b.m[key] = val
	b.mu.Unlock()
	return val, false
}

func (b *BucketStore) Delete(key string) {
	b.mu.Lock()
	delete(b.m, key)
	b.mu.Unlock()
}

func (b *BucketStore) Snapshot() map[string]*Leaky {
	b.mu.Lock()
	snap := maps.Clone(b.m)
	b.mu.Unlock()
	return snap
}

func (b *BucketStore) Len() int {
	b.mu.Lock()
	n := len(b.m)
	b.mu.Unlock()
	return n
}

// BeginPour blocks while a dump/snapshot is in progress.
//
// The returned function *must* be called exactly once, usually deferred, after the event has been poured.
func (b *BucketStore) BeginPour() (end func()) {
	b.muFlow.RLock()
	return b.muFlow.RUnlock
}

// FreezePours prevents new pours to start and waits for in-flight pours to finish.
//
// The returned function *must* be called exactly once, usually deferred, to allow pouring again.
func (b *BucketStore) FreezePours() (resume func()) {
	b.muFlow.Lock()
	return b.muFlow.Unlock
}
