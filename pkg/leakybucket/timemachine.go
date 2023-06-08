package leakybucket

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/time/rate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func TimeMachinePour(l *Leaky, msg types.Event) {
	var (
		d                 time.Time
		err               error
		special, rollback bool
	)
	if msg.MarshaledTime == "" {
		log.WithFields(log.Fields{
			"evt_type": msg.Line.Labels["type"],
			"evt_src":  msg.Line.Src,
			"scenario": l.Name,
		}).Warningf("Trying to process event without evt.StrTime. Event cannot be poured to scenario")
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

	// special edge case: the event we just received was before the first event
	if l.First_ts.After(d) {
		rollback = true
		l.First_ts = d
	}

	// special case: the event we just received wasn't the last
	if l.Last_ts.After(d) {
		special = true
	} else {
		l.Last_ts = d
	}
	l.mutex.Unlock()

	// In this case we recreate the limiter, and we pray that the Queue holds all events
	// In case it doesn't we skip this step and we accept that we may miss an overflow
	// But most of the time we have now two events in Queue
	if rollback && l.Total_count <= l.Queue.L {
		var timestamp time.Time
		for _, event := range l.Queue.GetQueue() {
			err = timestamp.UnmarshalText([]byte(event.MarshaledTime))
			if err != nil {
				log.Warningf("Failed unmarshaling event time (%s) : %v", msg.MarshaledTime, err)
				return
			}
			if !l.Limiter.AllowN(timestamp, 1) {
				l.Ovflw_ts = d
				l.logger.Debugf("Bucket overflow at %s", l.Ovflw_ts)
				l.Queue.Add(msg)
				l.Out <- l.Queue
				return
			}
		}
	}

	// In this case the last event we got is before the precedent event
	// let's sort it out
	if special {
		elapsed := l.Last_ts.Sub(d)
		consumed_tokens := elapsed.Seconds() * float64(rate.Every(l.Leakspeed))
		st := l.Limiter.Dump()
		st.Tokens -= consumed_tokens
		fmt.Printf("special case: %f", consumed_tokens)
		if st.Tokens < 0 {
			l.Ovflw_ts = l.Last_ts
			l.logger.Debugf("Bucket overflow at %s", l.Ovflw_ts)
			l.Queue.Add(msg)
			l.Out <- l.Queue
			return
		}
		l.Limiter.Load(st)
		return
	}

	if l.Limiter.AllowN(d, 1) {
		l.logger.Tracef("Time-Pouring event %s (tokens:%f)", d, l.Limiter.GetTokensCount())
		l.Queue.Add(msg)
	} else {
		l.Ovflw_ts = d
		l.logger.Debugf("Bucket overflow at %s", l.Ovflw_ts)
		l.Queue.Add(msg)
		l.Out <- l.Queue
	}
	//fmt.Printf("bucket after: %+v\n", *l)
}

func NewTimeMachine(g BucketFactory) *Leaky {
	l := NewLeaky(g)
	g.logger.Tracef("Instantiating timeMachine bucket")
	l.Pour = TimeMachinePour
	l.Mode = types.TIMEMACHINE
	return l
}
