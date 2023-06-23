package leakybucket

import (
	"fmt"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

type timestamp struct {
	t     time.Time
	mutex *sync.Mutex
}

func (l *Leaky) InitTimestamp() *timestamp {
	return &timestamp{
		mutex: &sync.Mutex{},
	}
}

func (l *Leaky) SetTimestamp(t time.Time) {
	l.timestamp.mutex.Lock()
	l.timestamp.t = t
	l.timestamp.mutex.Unlock()
}

func (l *Leaky) GetTimestamp() time.Time {
	l.timestamp.mutex.Lock()
	defer l.timestamp.mutex.Unlock()
	return l.timestamp.t
}

func TimeMachinePour(l *Leaky, msg types.Event) {
	var (
		d   time.Time
		err error
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
	if l.GetFirstEvent().IsZero() {
		l.logger.Debugf("First event, bucket creation time : %s", d)
		l.SetFirstEvent(d)
	}
	l.SetLastEvent(d)

	if l.Limiter.AllowN(d, 1) {
		l.logger.Tracef("Time-Pouring event %s (tokens:%f)", d, l.Limiter.GetTokensCount())
		l.Queue.Add(msg)
		fmt.Printf("test\n")
		if l.orderEvent {
			orderEvent[l.Mapkey].Done()
		}
	} else {
		l.Ovflw_ts = d
		l.logger.Debugf("Bucket overflow at %s", l.Ovflw_ts)
		l.Queue.Add(msg)
		l.Out <- l.Queue
	}
	//	fmt.Printf("Limiter: %+v", spew.Sdump(l.Limiter))
}

func NewTimeMachine(g BucketFactory) *Leaky {
	l := NewLeaky(g)
	g.logger.Tracef("Instantiating timeMachine bucket")
	l.Pour = TimeMachinePour
	l.Mode = types.TIMEMACHINE
	return l
}
