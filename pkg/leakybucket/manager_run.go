package leakybucket

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

/*
The leaky routines lifecycle are based on "real" time.
But when we are running in time-machine mode, the reference time is in logs and not "real" time.
Thus we need to garbage collect them to avoid a skyrocketing memory usage.
*/
func GarbageCollectBuckets(deadline time.Time, bucketStore *BucketStore) {
	resume := bucketStore.FreezePours()
	// to be on the safe side, keep the freeze lock for the whole function
	defer resume()

	snap := bucketStore.Snapshot()

	toflush := []string{}
	for key, val := range snap {
		// bucket already overflowed, we can kill it
		if !val.Ovflw_ts.IsZero() {
			val.logger.Debugf("overflowed at %s.", val.Ovflw_ts)
			toflush = append(toflush, key)
			val.cancel()
			continue
		}

		const eps = 1e-9

		tokat := val.Limiter.GetTokensCountAt(deadline)
		tokcapa := float64(val.Factory.Spec.Capacity)

		// bucket actually underflowed based on log time, but no in real time
		if tokat+eps >= tokcapa {
			metrics.BucketsUnderflow.With(prometheus.Labels{"name": val.Factory.Spec.Name}).Inc()
			val.logger.Debugf("UNDERFLOW : first_ts:%s tokens_at:%f capcity:%f", val.First_ts, tokat, tokcapa)
			toflush = append(toflush, key)
			val.cancel()
			continue
		}

		val.logger.Tracef("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
	}

	log.Infof("Cleaned %d buckets", len(toflush))
	for _, flushkey := range toflush {
		bucketStore.Delete(flushkey)
	}
}

func PourItemToBucket(
	ctx context.Context,
	bucket *Leaky,
	holder *BucketFactory,
	bucketStore *BucketStore,
	parsed *pipeline.Event,
	collector *PourCollector,
) error {
	var buckey = bucket.Mapkey
	var err error

	sigclosed := 0
	failed_sent := 0
	attempts := 0
	start := time.Now().UTC()

	for {
		attempts += 1
		/* Warn the user if we used more than a 100 ms to pour an event, it's at least an half lock*/
		if attempts%100000 == 0 && start.Add(100*time.Millisecond).Before(time.Now().UTC()) {
			holder.logger.Warningf("stuck for %s sending event to %s (sigclosed:%d failed_sent:%d attempts:%d)", time.Since(start),
				buckey, sigclosed, failed_sent, attempts)
		}

		/* check if leak routine is up */
		select {
		case <-bucket.done:
			// the bucket was found and dead, get a new one and continue
			bucket.logger.Tracef("Bucket %s found dead, cleanup the body", buckey)
			bucketStore.Delete(buckey)
			sigclosed += 1
			bucket, err = LoadOrStoreBucketFromHolder(ctx, buckey, bucketStore, holder, parsed.ExpectMode)
			if err != nil {
				return err
			}
			continue
			// holder.logger.Tracef("Signal exists, try to pour :)")
		default:
			// nothing to read, but not closed, try to pour
			// holder.logger.Tracef("Signal exists but empty, try to pour :)")
		}

		// let's see if this time-bucket should have expired
		if bucket.Mode == pipeline.TIMEMACHINE {
			bucket.mutex.Lock()
			firstTs := bucket.First_ts
			lastTs := bucket.Last_ts
			bucket.mutex.Unlock()

			if !firstTs.IsZero() {
				var d time.Time
				err = d.UnmarshalText([]byte(parsed.MarshaledTime))
				if err != nil {
					holder.logger.Warningf("Failed to parse event time (%s) : %v", parsed.MarshaledTime, err)
				}
				if d.After(lastTs.Add(bucket.Duration)) {
					bucket.logger.Tracef("bucket is expired (curr event: %s, bucket deadline: %s), kill", d, lastTs.Add(bucket.Duration))
					bucketStore.Delete(buckey)
					// not sure about this, should we create a new one ?
					sigclosed += 1
					bucket, err = LoadOrStoreBucketFromHolder(ctx, buckey, bucketStore, holder, parsed.ExpectMode)
					if err != nil {
						return err
					}
					continue
				}
			}
		}
		// the bucket seems to be up & running
		select {
		case bucket.In <- parsed:
			// holder.logger.Tracef("Successfully sent !")
			if collector != nil {
				evt := deepcopy.Copy(*parsed).(pipeline.Event)
				collector.Add(bucket.Factory.Spec.Name, evt)
			}
			holder.logger.Debugf("bucket '%s' is poured", holder.Spec.Name)
			return nil
		default:
			failed_sent += 1
			// holder.logger.Tracef("Failed to send, try again")
			continue

		}
	}
}

func LoadOrStoreBucketFromHolder(
	ctx context.Context,
	partitionKey string,
	buckets *BucketStore,
	holder *BucketFactory,
	expectMode int,
) (*Leaky, error) {
	leaky, ok := buckets.Load(partitionKey)
	if ok {
		return leaky, nil
	}

	/* the bucket doesn't exist, create it !*/
	var fresh_bucket *Leaky

	switch expectMode {
	case pipeline.TIMEMACHINE:
		fresh_bucket = NewTimeMachine(holder)
		holder.logger.Debugf("Creating TimeMachine bucket")
	case pipeline.LIVE:
		fresh_bucket = NewLeakyFromFactory(holder)
		holder.logger.Debugf("Creating Live bucket")
	default:
		return nil, fmt.Errorf("input event has no expected mode : %+v", expectMode)
	}
	fresh_bucket.In = make(chan *pipeline.Event)
	fresh_bucket.Mapkey = partitionKey
	fresh_bucket.ready = make(chan struct{})
	fresh_bucket.done = make(chan struct{})
	actual, stored := buckets.LoadOrStore(partitionKey, fresh_bucket)
	if !stored {
		go func() {
			ctx, cancel := context.WithCancel(ctx)
			fresh_bucket.cancel = cancel
			fresh_bucket.LeakRoutine(ctx, buckets)
		}()
		leaky = fresh_bucket
		// once the created goroutine is ready to process event, we can return it
		<-fresh_bucket.ready
	} else {
		holder.logger.Debugf("Unexpectedly found exisint bucket for %s", partitionKey)
		leaky = actual
	}
	holder.logger.Debugf("Created new bucket %s", partitionKey)
	return leaky, nil
}

var orderEvent map[string]*sync.WaitGroup

func PourItemToHolders(
	ctx context.Context,
	parsed pipeline.Event,
	holders []BucketFactory,
	buckets *BucketStore,
	collector *PourCollector,
) (bool, error) {
	var ok, condition, poured bool

	if collector != nil {
		evt := deepcopy.Copy(parsed).(pipeline.Event)
		collector.Add("OK", evt)
	}
	// find the relevant holders (scenarios)
	for idx := range holders {
		// for idx, holder := range holders {
		// evaluate bucket's condition
		if holders[idx].RunTimeFilter != nil {
			holders[idx].logger.Tracef("event against holder %d/%d", idx, len(holders))
			output, err := exprhelpers.Run(holders[idx].RunTimeFilter,
				map[string]any{"evt": &parsed},
				holders[idx].logger,
				holders[idx].Spec.Debug)
			if err != nil {
				holders[idx].logger.Errorf("failed parsing : %v", err)
				return false, fmt.Errorf("leaky failed : %s", err)
			}
			// we assume we a bool should add type check here
			if condition, ok = output.(bool); !ok {
				holders[idx].logger.Errorf("unexpected non-bool return : %T", output)
				holders[idx].logger.Fatalf("Filter issue")
			}
			if !condition {
				holders[idx].logger.Debugf("Event leaving node : ko (filter mismatch)")
				continue
			}
		}

		// groupby determines the partition key for the specific bucket
		var groupby string
		if holders[idx].RunTimeGroupBy != nil {
			tmpGroupBy, err := exprhelpers.Run(holders[idx].RunTimeGroupBy, map[string]any{"evt": &parsed}, holders[idx].logger, holders[idx].Spec.Debug)
			if err != nil {
				holders[idx].logger.Errorf("failed groupby : %v", err)
				return false, errors.New("leaky failed :/")
			}

			if groupby, ok = tmpGroupBy.(string); !ok {
				holders[idx].logger.Fatalf("failed groupby type : %v", err)
				return false, errors.New("groupby wrong type")
			}
		}
		buckey := holders[idx].BucketKey(groupby)

		// we need to either find the existing bucket, or create a new one (if it's the first event to hit it for this partition key)
		bucket, err := LoadOrStoreBucketFromHolder(ctx, buckey, buckets, &holders[idx], parsed.ExpectMode)
		if err != nil {
			return false, fmt.Errorf("failed to load or store bucket: %w", err)
		}
		// finally, pour the even into the bucket

		if bucket.orderEvent {
			if orderEvent == nil {
				orderEvent = make(map[string]*sync.WaitGroup)
			}
			if orderEvent[buckey] != nil {
				orderEvent[buckey].Wait()
			} else {
				orderEvent[buckey] = &sync.WaitGroup{}
			}

			orderEvent[buckey].Add(1)
		}

		err = PourItemToBucket(ctx, bucket, &holders[idx], buckets, &parsed, collector)

		if bucket.orderEvent {
			orderEvent[buckey].Wait()
		}

		if err != nil {
			return false, fmt.Errorf("failed to pour bucket: %w", err)
		}
		poured = true
	}
	return poured, nil
}
