package leakybucket

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Trigger struct {
	DumbProcessor
}

func (t *Trigger) OnBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	// Pour makes the bucket overflow all the time
	// TriggerPour unconditionally overflows
	return func(msg types.Event, l *Leaky) *types.Event {
		now := time.Now().UTC()

		if l.Mode == types.TIMEMACHINE {
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
