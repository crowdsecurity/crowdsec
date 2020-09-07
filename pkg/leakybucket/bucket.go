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
func NewLeaky(bucketFactory BucketFactory) *Leaky {
	bucketFactory.logger.Tracef("Instantiating live bucket %s", bucketFactory.Name)
	return FromFactory(bucketFactory)
}

func FromFactory(bucketFactory BucketFactory) *Leaky {
	var limiter rate.RateLimiter
	//golang rate limiter. It's mainly intended for http rate limiter
	Qsize := bucketFactory.Capacity
	if bucketFactory.CacheSize > 0 {
		//cache is smaller than actual capacity
		if bucketFactory.CacheSize <= bucketFactory.Capacity {
			Qsize = bucketFactory.CacheSize
			//bucket might be counter (infinite size), allow cache limitation
		} else if bucketFactory.Capacity == -1 {
			Qsize = bucketFactory.CacheSize
		}
	}
	if bucketFactory.Capacity == -1 {
		//In this case we allow all events to pass.
		//maybe in the future we could avoid using a limiter
		limiter = &rate.AlwaysFull{}
	} else {
		limiter = rate.NewLimiter(rate.Every(bucketFactory.leakspeed), bucketFactory.Capacity)
	}
	BucketsInstanciation.With(prometheus.Labels{"name": bucketFactory.Name}).Inc()

	//create the leaky bucket per se
	l := &Leaky{
		Name:         bucketFactory.Name,
		Limiter:      limiter,
		Uuid:         namegenerator.NewNameGenerator(time.Now().UTC().UnixNano()).Generate(),
		Queue:        NewQueue(Qsize),
		CacheSize:    bucketFactory.CacheSize,
		Out:          make(chan *Queue, 1),
		AllOut:       bucketFactory.ret,
		Capacity:     bucketFactory.Capacity,
		Leakspeed:    bucketFactory.leakspeed,
		BucketConfig: &bucketFactory,
		Pour:         Pour,
		Scope:        bucketFactory.Scope,
		Reprocess:    bucketFactory.Reprocess,
		Profiling:    bucketFactory.Profiling,
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
func LeakRoutine(leaky *Leaky) {

	var (
		durationTicker <-chan time.Time = make(<-chan time.Time)
	)

	BucketsCurrentCount.With(prometheus.Labels{"name": leaky.Name}).Inc()
	defer BucketsCurrentCount.With(prometheus.Labels{"name": leaky.Name}).Dec()

	/*todo : we create a logger at runtime while we want leakroutine to be up asap, might not be a good idea*/
	leaky.logger = leaky.BucketConfig.logger.WithFields(log.Fields{"capacity": leaky.Capacity, "partition": leaky.Mapkey, "bucket_id": leaky.Uuid})

	leaky.Signal <- true
	atomic.AddInt64(&LeakyRoutineCount, 1)
	defer atomic.AddInt64(&LeakyRoutineCount, -1)

	for _, f := range leaky.BucketConfig.processors {
		err := f.OnBucketInit(leaky.BucketConfig)
		if err != nil {
			leaky.logger.Errorf("Problem at bucket initializiation. Bail out %T : %v", f, err)
			close(leaky.Signal)
			return
		}
	}

	leaky.logger.Debugf("Leaky routine starting, lifetime : %s", leaky.Duration)
	for {
		select {
		/*receiving an event*/
		case msg := <-leaky.In:
			/*the msg var use is confusing and is redeclared in a different type :/*/
			for _, processor := range leaky.BucketConfig.processors {
				msg := processor.OnBucketPour(leaky.BucketConfig)(msg, leaky)

			for _, processor := range l.BucketConfig.processors {
				msg := processor.OnBucketPour(l.BucketConfig)(msg, l)
				// if &msg == nil we stop processing
				if msg == nil {
					goto End
				}
			}
			leaky.logger.Tracef("Pour event: %s", spew.Sdump(msg))
			leaky.logger.Debugf("Pouring event.")

			BucketsPour.With(prometheus.Labels{"name": leaky.Name, "source": msg.Line.Src}).Inc()

			leaky.Pour(leaky, msg) // glue for now
			//Clear cache on behalf of pour
			tmp := time.NewTicker(leaky.Duration)
			durationTicker = tmp.C
			leaky.Signal <- true
			defer tmp.Stop()
		/*a kill chan to allow externally killing the leaky routines*/
		case <-leaky.KillSwitch:
			close(leaky.Signal)
			leaky.logger.Debugf("Bucket externally killed, return")
			leaky.AllOut <- types.Event{Type: types.OVFLW, Mapkey: leaky.Mapkey}
			return
		/*we overflowed*/
		case ofw := <-leaky.Out:
			close(leaky.Signal)
			alert := NewAlert(leaky, ofw)
			leaky.logger.Tracef("Overflow hooks time : %v", leaky.BucketConfig.processors)
			for _, f := range leaky.BucketConfig.processors {
				alert, ofw = f.OnBucketOverflow(leaky.BucketConfig)(leaky, alert, ofw)
				if ofw == nil {
					leaky.logger.Debugf("Overflow has been discard (%T)", f)
					break
				}
			}
			leaky.logger.Tracef("Overflow event: %s", spew.Sdump(types.Alert(alert)))
			mt, _ := leaky.Ovflw_ts.MarshalText()
			leaky.logger.Tracef("overflow time : %s", mt)

			BucketsOverflow.With(prometheus.Labels{"name": leaky.Name}).Inc()
			leaky.logger.Infof("Pouet: %s", spew.Sdump(alert))

			leaky.AllOut <- types.Event{Overflow: alert, Type: types.OVFLW, MarshaledTime: string(mt)}
			return
			/*we underflow or reach bucket deadline (timers)*/
		case <-durationTicker:
			leaky.Ovflw_ts = time.Now()
			close(leaky.Signal)
			ofw := leaky.Queue
			alert := types.Alert{Mapkey: leaky.Mapkey}

			if leaky.timedOverflow {
				BucketsOverflow.With(prometheus.Labels{"name": leaky.Name}).Inc()

				alert = NewAlert(leaky, ofw)
				for _, f := range leaky.BucketConfig.processors {
					alert, ofw = f.OnBucketOverflow(leaky.BucketConfig)(leaky, alert, ofw)
					if ofw == nil {
						leaky.logger.Debugf("Overflow has been discard (%T)", f)
						break
					}
				}
				leaky.logger.Infof("Timed Overflow")
			} else {
				leaky.logger.Debugf("bucket underflow, destroy")
				BucketsUnderflow.With(prometheus.Labels{"name": leaky.Name}).Inc()

			}
			leaky.logger.Tracef("Overflow event: %s", spew.Sdump(types.Event{Overflow: alert}))


			leaky.AllOut <- types.Event{Overflow: alert, Type: types.OVFLW, Mapkey: leaky.Mapkey}
			leaky.logger.Tracef("Returning from leaky routine.")
			return
		}
	End:
	}
}

func Pour(leaky *Leaky, msg types.Event) {

	leaky.Total_count += 1
	if leaky.First_ts.IsZero() {
		leaky.First_ts = time.Now()
	}
	leaky.Last_ts = time.Now()
	if leaky.Limiter.Allow() {
		leaky.Queue.Add(msg)
	} else {
		leaky.Ovflw_ts = time.Now()
		leaky.logger.Debugf("Last event to be poured, bucket overflow.")
		leaky.Queue.Add(msg)
		leaky.Out <- leaky.Queue
	}
}
