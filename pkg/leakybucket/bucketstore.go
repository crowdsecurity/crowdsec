package leakybucket

import (
	"crypto/sha1"
	"fmt"
	"maps"
	"sync"
)

// BucketStore is the struct used to hold buckets during the lifecycle of the app
// (i.e. between reloads).
type BucketStore struct {
	wgDumpState *sync.WaitGroup
	wgPour      *sync.WaitGroup
	mu sync.Mutex
	m map[string]*Leaky
}

func NewBucketStore() *BucketStore {
	return &BucketStore{
		wgDumpState: &sync.WaitGroup{},
		wgPour:      &sync.WaitGroup{},
		m:           make(map[string]*Leaky),
	}
}

func GetKey(bucketCfg *BucketFactory, stackkey string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(bucketCfg.Filter+stackkey+bucketCfg.Name)))
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
