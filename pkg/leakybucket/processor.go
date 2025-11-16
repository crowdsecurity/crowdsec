package leakybucket

import (
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory) func(pipeline.Event, *Leaky) *pipeline.Event
	OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, pipeline.RuntimeAlert, *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue)

	AfterBucketPour(Bucket *BucketFactory) func(pipeline.Event, *Leaky) *pipeline.Event
}

type DumbProcessor struct{}

func (*DumbProcessor) OnBucketInit(bucketFactory *BucketFactory) error {
	return nil
}

func (*DumbProcessor) OnBucketPour(bucketFactory *BucketFactory) func(pipeline.Event, *Leaky) *pipeline.Event {
	return func(msg pipeline.Event, leaky *Leaky) *pipeline.Event {
		return &msg
	}
}

func (*DumbProcessor) OnBucketOverflow(b *BucketFactory) func(*Leaky, pipeline.RuntimeAlert, *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return func(leaky *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
		return alert, queue
	}
}

func (*DumbProcessor) AfterBucketPour(bucketFactory *BucketFactory) func(pipeline.Event, *Leaky) *pipeline.Event {
	return func(msg pipeline.Event, leaky *Leaky) *pipeline.Event {
		return &msg
	}
}
