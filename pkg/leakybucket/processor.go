package leakybucket

import (
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event
	OnBucketOverflow(Bucket *BucketFactory, leaky *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue)

	AfterBucketPour(Bucket *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event
}

type DumbProcessor struct{}

func (*DumbProcessor) OnBucketInit(_ *BucketFactory) error {
	return nil
}

func (*DumbProcessor) OnBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
}

func (*DumbProcessor) OnBucketOverflow(_ *BucketFactory, _ *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return alert, queue
}

func (*DumbProcessor) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
}
