package leakybucket

import "github.com/crowdsecurity/crowdsec/pkg/types"

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
	OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue)
}

type DumbProcessor struct {
}

func (d *DumbProcessor) OnBucketInit(bucketFactory *BucketFactory) error {
	return nil
}

func (d *DumbProcessor) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}

func (d *DumbProcessor) OnBucketOverflow(b *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue) {
	return func(leaky *Leaky, alert types.Alert, queue *Queue) (types.Alert, *Queue) {
		return alert, queue
	}

}
