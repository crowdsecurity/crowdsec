package leakybucket

import "github.com/crowdsecurity/crowdsec/pkg/types"

type Processor interface {
	OnBucketInit(Bucket *BucketFactory) error
	OnBucketPour(Bucket *BucketFactory) func(types.Event, *Leaky) *types.Event
	OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue)
}

type DumbProcessor struct {
}

func (d *DumbProcessor) OnBucketInit(b *BucketFactory) error {
	return nil
}

func (d *DumbProcessor) OnBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {
		return &msg
	}
}

func (d *DumbProcessor) OnBucketOverflow(b *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue) {
	return func(l *Leaky, s types.Alert, q *Queue) (types.Alert, *Queue) {
		return s, q
	}

}
