package leakybucket

import "github.com/crowdsecurity/crowdsec/pkg/types"

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
	OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.RuntimeAlert, *types.Queue) (types.RuntimeAlert, *types.Queue)

	AfterBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
}

type DumbProcessor struct{}

func (*DumbProcessor) OnBucketInit(bucketFactory *BucketFactory) error {
	return nil
}

func (*DumbProcessor) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}

func (*DumbProcessor) OnBucketOverflow(b *BucketFactory) func(*Leaky, types.RuntimeAlert, *types.Queue) (types.RuntimeAlert, *types.Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *types.Queue) (types.RuntimeAlert, *types.Queue) {
		return alert, queue
	}
}

func (*DumbProcessor) AfterBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}
