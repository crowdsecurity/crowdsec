package leakybucket

import (
	"crypto/sha1"
	"fmt"
	"sync"
)

// BucketStore is the struct used to hold buckets during the lifecycle of the app
// (i.e. between reloads).
type BucketStore struct {
	wgDumpState *sync.WaitGroup
	wgPour      *sync.WaitGroup
	m *sync.Map
}

func NewBucketStore() *BucketStore {
	return &BucketStore{
		wgDumpState: &sync.WaitGroup{},
		wgPour:      &sync.WaitGroup{},
		m:           &sync.Map{},
	}
}

func GetKey(bucketCfg *BucketFactory, stackkey string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(bucketCfg.Filter+stackkey+bucketCfg.Name)))
}


func (b *BucketStore) Load(key string) (*Leaky, bool) {
	v, ok := b.m.Load(key)
	if !ok {
		return nil, false
	}
	return v.(*Leaky), true
}

func (b *BucketStore) LoadOrStore(key string, val *Leaky) (*Leaky, bool) {
	actual, loaded := b.m.LoadOrStore(key, val)
	return actual.(*Leaky), loaded
}

func (b *BucketStore) Delete(key string) {
	b.m.Delete(key)
}

func (b *BucketStore) Range(fn func(string, *Leaky) bool) {
	b.m.Range(func(k, v any) bool {
		return fn(k.(string), v.(*Leaky))
	})
}

func (b *BucketStore) Len() int {
	n := 0
	b.m.Range(func(_ any, _ any) bool {
		n++; return true
	})

	return n
}
