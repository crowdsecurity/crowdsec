package leakybucket

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type Trigger struct {
	DumbProcessor
}

func (t *Trigger) OnBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	// Pour makes the bucket overflow all the time
	// TriggerPour unconditionnaly overflows
	return func(msg types.Event, l *Leaky) *types.Event {
		if l.Mode == TIMEMACHINE {
			var d time.Time
			err := d.UnmarshalText([]byte(msg.MarshaledTime))
			if err != nil {
				log.Warningf("Failed unmarshaling event time (%s) : %v", msg.MarshaledTime, err)
				d = time.Now().UTC()
			}
			l.logger.Debugf("yay timemachine overflow time : %s --> %s", d, msg.MarshaledTime)
			l.Last_ts = d
			l.First_ts = d
			l.Ovflw_ts = d
		} else {
			l.Last_ts = time.Now().UTC()
			l.First_ts = time.Now().UTC()
			l.Ovflw_ts = time.Now().UTC()
		}
		l.Total_count = 1

		l.logger.Infof("Bucket overflow")
		l.Queue.Add(msg)
		l.Out <- l.Queue

		return nil
	}
}
