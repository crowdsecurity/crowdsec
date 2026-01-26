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
	Bucket_map  *sync.Map
}

func NewBucketStore() *BucketStore {
	return &BucketStore{
		wgDumpState: &sync.WaitGroup{},
		wgPour:      &sync.WaitGroup{},
		Bucket_map:  &sync.Map{},
	}
}

func GetKey(bucketCfg BucketFactory, stackkey string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(bucketCfg.Filter+stackkey+bucketCfg.Name)))
}
