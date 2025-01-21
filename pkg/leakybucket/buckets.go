package leakybucket

import (
	"crypto/sha1"
	"fmt"
	"sync"
)

// Buckets is the struct used to hold buckets in the context of
// main.go the idea is to have one struct to rule them all
type Buckets struct {
	wgDumpState *sync.WaitGroup
	wgPour      *sync.WaitGroup
	Bucket_map  *sync.Map
}

// NewBuckets create the Buckets struct
func NewBuckets() *Buckets {
	return &Buckets{
		wgDumpState: &sync.WaitGroup{},
		wgPour:      &sync.WaitGroup{},
		Bucket_map:  &sync.Map{},
	}
}

func GetKey(bucketCfg BucketFactory, stackkey string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(bucketCfg.Filter+stackkey+bucketCfg.Name)))
}
