package leakybucket

import (
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

func TimeMachinePour(l *Leaky, msg types.Event) {
	var (
		d   time.Time
		err error
	)
	if msg.MarshaledTime == "" {
		log.Warningf("Trying to time-machine event without timestamp : %s", spew.Sdump(msg))
		return
	}

	err = d.UnmarshalText([]byte(msg.MarshaledTime))
	if err != nil {
		log.Warningf("Failed unmarshaling event time (%s) : %v", msg.MarshaledTime, err)
		return
	}

	l.Total_count += 1
	l.mutex.Lock()
	if l.First_ts.IsZero() {
		l.logger.Debugf("First event, bucket creation time : %s", d)
		l.First_ts = d
	}
	l.Last_ts = d
	l.mutex.Unlock()

	if l.Limiter.AllowN(d, 1) {
		l.logger.Tracef("Time-Pouring event %s (tokens:%f)", d, l.Limiter.GetTokensCount())
		l.Queue.Add(msg)
	} else {
		l.Ovflw_ts = d
		l.logger.Debugf("Bucket overflow at %s", l.Ovflw_ts)
		l.Queue.Add(msg)
		l.Out <- l.Queue
	}
}

func NewTimeMachine(g BucketFactory) *Leaky {
	l := NewLeaky(g)
	g.logger.Tracef("Instantiating timeMachine bucket")
	l.Pour = TimeMachinePour
	l.Mode = TIMEMACHINE
	return l
}
