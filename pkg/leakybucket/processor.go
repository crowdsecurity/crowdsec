package leakybucket

import (
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Processor interface {
	Description() string
	OnBucketPour(f *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event
	OnBucketOverflow(f *BucketFactory, leaky *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue)

	AfterBucketPour(f *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event
}

type DumbProcessor struct{}

func (*DumbProcessor) Description() string {
	return ""
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
