package leakybucket

import (
	"sync/atomic"
	"time"

	//"log"
	"github.com/crowdsecurity/crowdsec/pkg/time/rate"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/goombaio/namegenerator"

	//rate "time/rate"

	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	//"golang.org/x/time/rate"
)

const (
	LIVE = iota
	TIMEMACHINE
)

//Leaky represents one instance of a bucket
type Leaky struct {
	Name string
	Mode int //LIVE or TIMEMACHINE
	//the limiter is what holds the proper "leaky aspect", it determines when/if we can pour objects
	Limiter         rate.RateLimiter `json:"-"`
	SerializedState rate.Lstate
	//Queue is used to held the cache of objects in the bucket, it is used to know 'how many' objects we have in buffer.
	Queue *Queue
	//Leaky buckets are receiving message through a chan
	In chan types.Event `json:"-"`
	//Leaky buckets are pushing their overflows through a chan
	Out chan *Queue `json:"-"`
	// shared for all buckets (the idea is to kill this afterwards)
	AllOut     chan types.Event `json:"-"`
	KillSwitch chan bool        `json:"-"`
	//max capacity (for burst)
	Capacity int
	//CacheRatio is the number of elements that should be kept in memory (compared to capacity)
	CacheSize int
	//the unique identifier of the bucket (a hash)
	Mapkey string
	// chan for signaling
	Signal       chan bool `json:"-"`
	Scope        string
	Reprocess    bool
	Uuid         string
	First_ts     time.Time
	Last_ts      time.Time
	Ovflw_ts     time.Time
	Total_count  int
	Leakspeed    time.Duration
	BucketConfig *BucketFactory
	Duration     time.Duration
	Pour         func(*Leaky, types.Event) `json:"-"`
	//Profiling when set to true enables profiling of bucket
	Profiling     bool
	timedOverflow bool
	logger        *log.Entry
}

var BucketsPour = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_poured_total",
		Help: "Total events were poured in bucket.",
	},
	[]string{"source", "name"},
)

var BucketsOverflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_overflowed_total",
		Help: "Total buckets overflowed.",
	},
	[]string{"name"},
)

var BucketsUnderflow = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_underflowed_total",
		Help: "Total buckets underflowed.",
	},
	[]string{"name"},
)

var BucketsInstanciation = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "cs_bucket_created_total",
		Help: "Total buckets were instanciated.",
	},
	[]string{"name"},
)

var BucketsCurrentCount = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "cs_buckets",
		Help: "Number of buckets that currently exist.",
	},
	[]string{"name"},
)

var LeakyRoutineCount int64

// Newleaky creates a new leaky bucket from a BucketFactory
// Events created by the bucket (overflow, bucket empty) are sent to a chan defined by BucketFactory
// The leaky bucket implementation is based on rate limiter (see https://godoc.org/golang.org/x/time/rate)
// There's a trick to have an event said when the bucket gets empty to allow its destruction
func NewLeaky(g BucketFactory) *Leaky {
	g.logger.Tracef("Instantiating live bucket %s", g.Name)
	return FromFactory(g)
}

func FromFactory(g BucketFactory) *Leaky {
	var limiter rate.RateLimiter
	//golang rate limiter. It's mainly intended for http rate limiter
	Qsize := g.Capacity
	if g.CacheSize > 0 {
		//cache is smaller than actual capacity
		if g.CacheSize <= g.Capacity {
			Qsize = g.CacheSize
			//bucket might be counter (infinite size), allow cache limitation
		} else if g.Capacity == -1 {
			Qsize = g.CacheSize
		}
	}
	if g.Capacity == -1 {
		//In this case we allow all events to pass.
		//maybe in the future we could avoid using a limiter
		limiter = &rate.AlwaysFull{}
	} else {
		limiter = rate.NewLimiter(rate.Every(g.leakspeed), g.Capacity)
	}
	BucketsInstanciation.With(prometheus.Labels{"name": g.Name}).Inc()

	//create the leaky bucket per se
	l := &Leaky{
		Name:         g.Name,
		Limiter:      limiter,
		Uuid:         namegenerator.NewNameGenerator(time.Now().UTC().UnixNano()).Generate(),
		Queue:        NewQueue(Qsize),
		CacheSize:    g.CacheSize,
		Out:          make(chan *Queue, 1),
		AllOut:       g.ret,
		Capacity:     g.Capacity,
		Leakspeed:    g.leakspeed,
		BucketConfig: &g,
		Pour:         Pour,
		Scope:        g.Scope,
		Reprocess:    g.Reprocess,
		Profiling:    g.Profiling,
		Mode:         LIVE,
	}
	if l.BucketConfig.Capacity > 0 && l.BucketConfig.leakspeed != time.Duration(0) {
		l.Duration = time.Duration(l.BucketConfig.Capacity+1) * l.BucketConfig.leakspeed
	}
	if l.BucketConfig.duration != time.Duration(0) {
		l.Duration = l.BucketConfig.duration
		l.timedOverflow = true
	}

	return l
}

/* for now mimic a leak routine */
//LeakRoutine us the life of a bucket. It dies when the bucket underflows or overflows
func LeakRoutine(l *Leaky) {

	var (
		durationTicker <-chan time.Time = make(<-chan time.Time)
	)

	BucketsCurrentCount.With(prometheus.Labels{"name": l.Name}).Inc()
	defer BucketsCurrentCount.With(prometheus.Labels{"name": l.Name}).Dec()

	/*todo : we create a logger at runtime while we want leakroutine to be up asap, might not be a good idea*/
	l.logger = l.BucketConfig.logger.WithFields(log.Fields{"capacity": l.Capacity, "partition": l.Mapkey, "bucket_id": l.Uuid})

	l.Signal <- true
	atomic.AddInt64(&LeakyRoutineCount, 1)
	defer atomic.AddInt64(&LeakyRoutineCount, -1)

	for _, f := range l.BucketConfig.processors {
		err := f.OnBucketInit(l.BucketConfig)
		if err != nil {
			l.logger.Errorf("Problem at bucket initializiation. Bail out %T : %v", f, err)
			close(l.Signal)
			return
		}
	}

	l.logger.Debugf("Leaky routine starting, lifetime : %s", l.Duration)
	for {
		select {
		/*receiving an event*/
		case msg := <-l.In:
			/*the msg var use is confusing and is redeclared in a different type :/*/
			for _, processor := range l.BucketConfig.processors {
				msg := processor.OnBucketPour(l.BucketConfig)(msg, l)
				// if &msg == nil we stop processing
				if msg == nil {
					goto End
				}
			}
			l.logger.Tracef("Pour event: %s", spew.Sdump(msg))
			l.logger.Debugf("Pouring event.")

			BucketsPour.With(prometheus.Labels{"name": l.Name, "source": msg.Line.Src}).Inc()

			l.Pour(l, msg) // glue for now
			//Clear cache on behalf of pour
			tmp := time.NewTicker(l.Duration)
			durationTicker = tmp.C
			l.Signal <- true
			defer tmp.Stop()
		/*a kill chan to allow externally killing the leaky routines*/
		case <-l.KillSwitch:
			close(l.Signal)
			l.logger.Debugf("Bucket externally killed, return")
			l.AllOut <- types.Event{Type: types.OVFLW, Mapkey: l.Mapkey}
			return
		/*we overflowed*/
		case ofw := <-l.Out:
			close(l.Signal)
			alert := NewAlert(l, ofw)
			l.logger.Tracef("Overflow hooks time : %v", l.BucketConfig.processors)
			for _, f := range l.BucketConfig.processors {
				alert, ofw = f.OnBucketOverflow(l.BucketConfig)(l, alert, ofw)
				if ofw == nil {
					l.logger.Debugf("Overflow has been discard (%T)", f)
					break
				}
			}
			l.logger.Tracef("Overflow event: %s", spew.Sdump(types.Alert(alert)))
			mt, _ := l.Ovflw_ts.MarshalText()
			l.logger.Tracef("overflow time : %s", mt)

			BucketsOverflow.With(prometheus.Labels{"name": l.Name}).Inc()
			l.logger.Infof("Pouet: %s", spew.Sdump(alert))

			l.AllOut <- types.Event{Overflow: alert, Type: types.OVFLW, MarshaledTime: string(mt)}
			return
			/*we underflow or reach bucket deadline (timers)*/
		case <-durationTicker:
			l.Ovflw_ts = time.Now()
			close(l.Signal)
			ofw := l.Queue
			alert := types.Alert{Mapkey: l.Mapkey}

			if l.timedOverflow {
				BucketsOverflow.With(prometheus.Labels{"name": l.Name}).Inc()

				alert = NewAlert(l, ofw)
				for _, f := range l.BucketConfig.processors {
					alert, ofw = f.OnBucketOverflow(l.BucketConfig)(l, alert, ofw)
					if ofw == nil {
						l.logger.Debugf("Overflow has been discard (%T)", f)
						break
					}
				}
				l.logger.Infof("Timed Overflow")
			} else {
				l.logger.Debugf("bucket underflow, destroy")
				BucketsUnderflow.With(prometheus.Labels{"name": l.Name}).Inc()

			}
			l.logger.Tracef("Overflow event: %s", spew.Sdump(types.Event{Overflow: alert}))

			l.AllOut <- types.Event{Overflow: alert, Type: types.OVFLW, Mapkey: l.Mapkey}
			l.logger.Tracef("Returning from leaky routine.")
			return
		}
	End:
	}
}

func Pour(l *Leaky, msg types.Event) {

	l.Total_count += 1
	if l.First_ts.IsZero() {
		l.First_ts = time.Now()
	}
	l.Last_ts = time.Now()
	if l.Limiter.Allow() {
		l.Queue.Add(msg)
	} else {
		l.Ovflw_ts = time.Now()
		l.logger.Debugf("Last event to be poured, bucket overflow.")
		l.Queue.Add(msg)
		l.Out <- l.Queue
	}
}
