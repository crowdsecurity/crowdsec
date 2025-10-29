package leakybucket

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Trigger struct {
	DumbProcessor
}

func (*Trigger) OnBucketPour(b *BucketFactory) func(pipeline.Event, *Leaky) *pipeline.Event {
	// Pour makes the bucket overflow all the time
	// TriggerPour unconditionally overflows
	return func(msg pipeline.Event, l *Leaky) *pipeline.Event {
		now := time.Now().UTC()

		if l.Mode == pipeline.TIMEMACHINE {
			var d time.Time

			err := d.UnmarshalText([]byte(msg.MarshaledTime))
			if err != nil {
				log.Warningf("Failed to parse event time (%s) : %v", msg.MarshaledTime, err)

				d = now
			}

			l.logger.Debugf("yay timemachine overflow time : %s --> %s", d, msg.MarshaledTime)
			l.Last_ts = d
			l.First_ts = d
			l.Ovflw_ts = d
		} else {
			l.Last_ts = now
			l.First_ts = now
			l.Ovflw_ts = now
		}

		l.Total_count = 1

		l.logger.Debug("Bucket overflow")
		l.Queue.Add(msg)
		l.Out <- l.Queue

		return nil
	}
}
