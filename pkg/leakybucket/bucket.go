package leakybucket

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type pourGate interface {
	BeginPour() func()
}

// Leaky represents one instance of a bucket
type Leaky struct {
	Name string
	Mode int // LIVE or TIMEMACHINE
	// the limiter is what holds the proper "leaky aspect", it determines when/if we can pour objects
	Limiter         rate.RateLimiter `json:"-"`
	SerializedState rate.Lstate
	// Queue is used to hold the cache of objects in the bucket, it is used to know 'how many' objects we have in buffer.
	Queue *pipeline.Queue
	// Leaky buckets are receiving message through a chan
	In chan *pipeline.Event `json:"-"`
	// Leaky buckets are pushing their overflows through a chan
	Out chan *pipeline.Queue `json:"-"`
	// shared for all buckets (the idea is to kill this afterward)
	AllOut chan pipeline.Event `json:"-"`
	// max capacity (for burst)
	Capacity int
	// CacheRatio is the number of elements that should be kept in memory (compared to capacity)
	CacheSize int
	// the unique identifier of the bucket (a hash)
	Mapkey string
	ready        chan struct{} // closed when LeakRoutine is ready
	readyOnce    sync.Once     // use to prevent double close
	done         chan struct{} // closed when LeakRoutine has stopped processing
	doneOnce     sync.Once     // use to prevent double close
	Suicide      chan bool `json:"-"`
	Reprocess    bool
	Uuid         string
	First_ts     time.Time
	Last_ts      time.Time
	Ovflw_ts     time.Time
	Total_count  int
	Leakspeed    time.Duration
	BucketConfig *BucketFactory
	Duration     time.Duration
	Pour         func(*Leaky, pourGate, pipeline.Event) `json:"-"`
	timedOverflow       bool
	conditionalOverflow bool
	logger              *log.Entry
	scopeType           ScopeType
	hash                string
	scenarioVersion     string
	mutex               *sync.Mutex // used only for TIMEMACHINE mode to allow garbage collection without races
	orderEvent          bool
	cancel              context.CancelFunc
	processors          []Processor
}

// NewLeakyFromFactory creates a new leaky bucket from a BucketFactory
// Events created by the bucket (overflow, bucket empty) are sent to a chan defined by BucketFactory
// The leaky bucket implementation is based on rate limiter (see https://godoc.org/golang.org/x/time/rate)
// There's a trick to have an event said when the bucket gets empty to allow its destruction
func NewLeakyFromFactory(f *BucketFactory) (*Leaky, error) {
	f.logger.Tracef("Instantiating live bucket %s", f.Spec.Name)

	var limiter rate.RateLimiter
	// golang rate limiter. It's mainly intended for http rate limiter
	Qsize := f.Spec.Capacity
	if f.Spec.CacheSize > 0 {
		// cache is smaller than actual capacity
		if f.Spec.CacheSize <= f.Spec.Capacity {
			Qsize = f.Spec.CacheSize
			// bucket might be counter (infinite size), allow cache limitation
		} else if f.Spec.Capacity == -1 {
			Qsize = f.Spec.CacheSize
		}
	}
	if f.Spec.Capacity == -1 {
		// In this case we allow all events to pass.
		// maybe in the future we could avoid using a limiter
		limiter = &rate.AlwaysFull{}
	} else {
		limiter = rate.NewLimiter(rate.Every(f.leakspeed), f.Spec.Capacity)
	}
	metrics.BucketsInstantiation.With(prometheus.Labels{"name": f.Spec.Name}).Inc()

	processors := make([]Processor, len(f.processorFactories))
	for i := range f.processorFactories {
		p, err := f.processorFactories[i](f)
		if err != nil {
			return nil, err
		}
		processors[i] = p
	}

	// create the leaky bucket per se
	l := &Leaky{
		Name:            f.Spec.Name,
		Limiter:         limiter,
		Uuid:            seed.Generate(),
		Queue:           pipeline.NewQueue(Qsize),
		CacheSize:       f.Spec.CacheSize,
		Out:             make(chan *pipeline.Queue, 1),
		Suicide:         make(chan bool, 1),
		AllOut:          f.ret,
		Capacity:        f.Spec.Capacity,
		Leakspeed:       f.leakspeed,
		BucketConfig:    f,
		Pour:            Pour,
		Reprocess:       f.Spec.Reprocess,
		Mode:            pipeline.LIVE,
		scopeType:       f.Spec.ScopeType,
		scenarioVersion: f.Spec.ScenarioVersion,
		hash:            f.hash,
		mutex:           &sync.Mutex{},
		orderEvent:      f.orderEvent,
		processors:	 processors,
	}
	if f.Spec.Capacity > 0 && f.leakspeed != time.Duration(0) {
		l.Duration = time.Duration(f.Spec.Capacity+1) * f.leakspeed
	}
	if f.duration != time.Duration(0) {
		l.Duration = f.duration
		l.timedOverflow = true
	}

	if f.Spec.Type == "conditional" {
		l.conditionalOverflow = true
		l.Duration = f.leakspeed
	}

	if f.Spec.Type == "bayesian" {
		l.Duration = f.leakspeed
	}
	return l, nil
}

// for now mimic a leak routine
// LeakRoutine is the life of a bucket. It dies when the bucket underflows or overflows
func (l *Leaky) LeakRoutine(ctx context.Context, gate pourGate) {
	var (
		durationTickerChan = make(<-chan time.Time)
		durationTicker     *time.Ticker
		firstEvent         = true
	)

	defer l.markDone()

	defer func() {
		if durationTicker != nil {
			durationTicker.Stop()
		}
	}()

	defer trace.CatchPanic(fmt.Sprintf("crowdsec/LeakRoutine/%s", l.Name))

	metrics.BucketsCurrentCount.With(prometheus.Labels{"name": l.Name}).Inc()
	defer metrics.BucketsCurrentCount.With(prometheus.Labels{"name": l.Name}).Dec()

	// TODO: we create a logger at runtime while we want leakroutine to be up asap, might not be a good idea
	l.logger = l.BucketConfig.logger.WithFields(log.Fields{"partition": l.Mapkey, "bucket_id": l.Uuid})

	l.markReady()

	l.logger.Debugf("Leaky routine starting, lifetime : %s", l.Duration)
	for {
		select {
		// receiving an event
		case msg := <-l.In:
			// the msg var use is confusing and is redeclared in a different type :/
			for _, processor := range l.processors {
				msg = processor.OnBucketPour(l.BucketConfig, *msg, l)
				// if &msg == nil we stop processing
				if msg == nil {
					if l.orderEvent {
						orderEvent[l.Mapkey].Done()
					}
					goto End
				}
			}
			if l.logger.Level >= log.TraceLevel {
				l.logger.Tracef("Pour event: %s", spew.Sdump(msg))
			}
			metrics.BucketsPour.With(prometheus.Labels{"name": l.Name, "source": msg.Line.Src, "type": msg.Line.Module}).Inc()

			l.Pour(l, gate, *msg) // glue for now

			for _, processor := range l.processors {
				msg = processor.AfterBucketPour(l.BucketConfig, *msg, l)
				if msg == nil {
					if l.orderEvent {
						orderEvent[l.Mapkey].Done()
					}
					goto End
				}
			}

			// Clear cache on behalf of pour

			// if durationTicker isn't initialized, then we're pouring our first event

			// reinitialize the durationTicker when it's not a counter bucket
			if l.Duration > 0 && (!l.timedOverflow || firstEvent) {
				if firstEvent {
					durationTicker = time.NewTicker(l.Duration)
					durationTickerChan = durationTicker.C
				} else {
					durationTicker.Reset(l.Duration)
				}
			}
			firstEvent = false
			// we overflowed
			if l.orderEvent {
				orderEvent[l.Mapkey].Done()
			}
		case ofw := <-l.Out:
			l.overflow(ofw)
			return
		// suiciiiide
		case <-l.Suicide:
			// don't wait defer to close the channel, in case we are blocked before returning
			l.markDone()
			metrics.BucketsCanceled.With(prometheus.Labels{"name": l.Name}).Inc()
			l.logger.Debugf("Suicide triggered")
			l.AllOut <- pipeline.Event{Type: pipeline.OVFLW, Overflow: pipeline.RuntimeAlert{Mapkey: l.Mapkey}}
			l.logger.Tracef("Returning from leaky routine.")
			return
		// we underflow or reach bucket deadline (timers)
		case <-durationTickerChan:
			var (
				alert pipeline.RuntimeAlert
				err   error
			)
			l.Ovflw_ts = time.Now().UTC()
			l.markDone()
			ofw := l.Queue
			alert = pipeline.RuntimeAlert{Mapkey: l.Mapkey}

			if l.timedOverflow {
				metrics.BucketsOverflow.With(prometheus.Labels{"name": l.Name}).Inc()

				alert, err = NewAlert(l, ofw)
				if err != nil {
					log.Error(err)
				}
				for _, f := range l.processors {
					alert, ofw = f.OnBucketOverflow(l.BucketConfig, l, alert, ofw)
					if ofw == nil {
						l.logger.Debugf("Overflow has been discarded (%T)", f)
						break
					}
				}
				l.logger.Infof("Timed Overflow")
			} else {
				l.logger.Debugf("bucket underflow, destroy")
				metrics.BucketsUnderflow.With(prometheus.Labels{"name": l.Name}).Inc()
			}
			if l.logger.Level >= log.TraceLevel {
				// don't sdump if it's not going to be printed, it's expensive
				l.logger.Tracef("Overflow event: %s", spew.Sdump(pipeline.Event{Overflow: alert}))
			}

			l.AllOut <- pipeline.Event{Overflow: alert, Type: pipeline.OVFLW}
			l.logger.Tracef("Returning from leaky routine.")
			return
		case <-ctx.Done():
			l.logger.Debugf("Bucket externally killed, return")
			for len(l.Out) > 0 {
				ofw := <-l.Out
				l.overflow(ofw)
			}
			l.AllOut <- pipeline.Event{Type: pipeline.OVFLW, Overflow: pipeline.RuntimeAlert{Mapkey: l.Mapkey}}
			return
		}
	End:
	}
}

// TODO: can't be method, a field has the same name
func Pour(l *Leaky, gate pourGate, msg pipeline.Event) {
	end := gate.BeginPour()
	defer end()

	l.Total_count += 1
	if l.First_ts.IsZero() {
		l.First_ts = time.Now().UTC()
	}
	l.Last_ts = time.Now().UTC()

	if l.Limiter.Allow() || l.conditionalOverflow {
		l.Queue.Add(msg)
	} else {
		l.Ovflw_ts = time.Now().UTC()
		l.logger.Debugf("Last event to be poured, bucket overflow.")
		l.Queue.Add(msg)
		l.Out <- l.Queue
	}
}

func (l *Leaky) overflow(ofw *pipeline.Queue) {
	l.markDone()
	alert, err := NewAlert(l, ofw)
	if err != nil {
		log.Errorf("%s", err)
	}
	l.logger.Tracef("Overflow hooks time : %v", l.processors)
	for _, f := range l.processors {
		alert, ofw = f.OnBucketOverflow(l.BucketConfig, l, alert, ofw)
		if ofw == nil {
			l.logger.Debugf("Overflow has been discarded (%T)", f)
			break
		}
	}
	if l.logger.Level >= log.TraceLevel {
		l.logger.Tracef("Overflow event: %s", spew.Sdump(alert))
	}
	mt, _ := l.Ovflw_ts.MarshalText()
	l.logger.Tracef("overflow time : %s", mt)

	metrics.BucketsOverflow.With(prometheus.Labels{"name": l.Name}).Inc()

	l.AllOut <- pipeline.Event{Overflow: alert, Type: pipeline.OVFLW, MarshaledTime: string(mt)}
}

func (l *Leaky) markReady() {
	l.readyOnce.Do(func() {
		close(l.ready)
	})
}

func (l *Leaky) markDone() {
	l.doneOnce.Do(func() {
		close(l.done)
	})
}

