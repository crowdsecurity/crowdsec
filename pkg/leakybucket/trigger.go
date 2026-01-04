package leakybucket

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Trigger struct {
	DumbProcessor
}

func (*Trigger) OnBucketPour(_ *BucketFactory, msg pipeline.Event, l *Leaky) *pipeline.Event {
	// Pour makes the bucket overflow all the time
	// TriggerPour unconditionally overflows
	// default if cannot parse
	ts := time.Now().UTC()

	if l.Mode == pipeline.TIMEMACHINE {
		var d time.Time

		if err := d.UnmarshalText([]byte(msg.MarshaledTime)); err != nil {
			log.Warningf("Failed to parse event time (%s): %v", msg.MarshaledTime, err)
		} else {
			ts = d
		}

		l.logger.Debugf("yay timemachine overflow time: %s --> %s", d, msg.MarshaledTime)
	}

	l.Last_ts = ts
	l.First_ts = ts
	l.Ovflw_ts = ts

	l.Total_count = 1

	l.logger.Debug("Bucket overflow")
	l.Queue.Add(msg)
	l.Out <- l.Queue

	return nil
}
