package leakybucket

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Trigger struct {
	DumbProcessor
}

func (t *Trigger) OnBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	// Pour makes the bucket overflow all the time
	// TriggerPour unconditionnaly overflows
	return func(msg types.Event, l *Leaky) *types.Event {
		l.Total_count = 1
		l.First_ts = time.Now()
		l.Ovflw_ts = time.Now()
		l.logger.Infof("Bucket overflow")
		l.Queue.Add(msg)
		l.Out <- l.Queue

		return nil
	}
}
