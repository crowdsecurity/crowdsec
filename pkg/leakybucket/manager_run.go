package leakybucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var serialized map[string]Leaky
var BucketPourCache map[string][]types.Event
var BucketPourTrack bool

/*
The leaky routines lifecycle are based on "real" time.
But when we are running in time-machine mode, the reference time is in logs and not "real" time.
Thus we need to garbage collect them to avoid a skyrocketing memory usage.
*/
func GarbageCollectBuckets(deadline time.Time, buckets *Buckets) error {
	buckets.wgPour.Wait()
	buckets.wgDumpState.Add(1)
	defer buckets.wgDumpState.Done()

	total := 0
	discard := 0
	toflush := []string{}
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
		key := rkey.(string)
		val := rvalue.(*Leaky)
		total += 1
		//bucket already overflowed, we can kill it
		if !val.Ovflw_ts.IsZero() {
			discard += 1
			val.logger.Debugf("overflowed at %s.", val.Ovflw_ts)
			toflush = append(toflush, key)
			val.tomb.Kill(nil)
			return true
		}
		/*FIXME : sometimes the gettokenscountat has some rounding issues when we try to
		match it with bucket capacity, even if the bucket has long due underflow. Round to 2 decimals*/
		tokat := val.Limiter.GetTokensCountAt(deadline)
		tokcapa := float64(val.Capacity)
		tokat = math.Round(tokat*100) / 100
		tokcapa = math.Round(tokcapa*100) / 100
		//bucket actually underflowed based on log time, but no in real time
		if tokat >= tokcapa {
			BucketsUnderflow.With(prometheus.Labels{"name": val.Name}).Inc()
			val.logger.Debugf("UNDERFLOW : first_ts:%s tokens_at:%f capcity:%f", val.First_ts, tokat, tokcapa)
			toflush = append(toflush, key)
			val.tomb.Kill(nil)
			return true
		}

		val.logger.Tracef("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		}
		log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)

		return true
	})
	log.Infof("Cleaned %d buckets", len(toflush))
	for _, flushkey := range toflush {
		buckets.Bucket_map.Delete(flushkey)
	}
	return nil
}

func DumpBucketsStateAt(deadline time.Time, outputdir string, buckets *Buckets) (string, error) {

	//synchronize with PourItemtoHolders
	buckets.wgPour.Wait()
	buckets.wgDumpState.Add(1)
	defer buckets.wgDumpState.Done()

	if outputdir == "" {
		return "", fmt.Errorf("empty output dir for dump bucket state")
	}
	tmpFd, err := os.CreateTemp(os.TempDir(), "crowdsec-buckets-dump-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file : %s", err)
	}
	defer tmpFd.Close()
	tmpFileName := tmpFd.Name()
	serialized = make(map[string]Leaky)
	log.Printf("Dumping buckets state at %s", deadline)
	total := 0
	discard := 0
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
		key := rkey.(string)
		val := rvalue.(*Leaky)
		total += 1
		if !val.Ovflw_ts.IsZero() {
			discard += 1
			val.logger.Debugf("overflowed at %s.", val.Ovflw_ts)
			return true
		}
		/*FIXME : sometimes the gettokenscountat has some rounding issues when we try to
		match it with bucket capacity, even if the bucket has long due underflow. Round to 2 decimals*/
		tokat := val.Limiter.GetTokensCountAt(deadline)
		tokcapa := float64(val.Capacity)
		tokat = math.Round(tokat*100) / 100
		tokcapa = math.Round(tokcapa*100) / 100

		if tokat >= tokcapa {
			BucketsUnderflow.With(prometheus.Labels{"name": val.Name}).Inc()
			val.logger.Debugf("UNDERFLOW : first_ts:%s tokens_at:%f capcity:%f", val.First_ts, tokat, tokcapa)
			discard += 1
			return true
		}
		val.logger.Debugf("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)

		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		}
		log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)
		val.SerializedState = val.Limiter.Dump()
		serialized[key] = *val
		return true
	})
	bbuckets, err := json.MarshalIndent(serialized, "", " ")
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshal buckets : %s", err)
	}
	size, err := tmpFd.Write(bbuckets)
	if err != nil {
		return "", fmt.Errorf("failed to write temp file : %s", err)
	}
	log.Infof("Serialized %d live buckets (+%d expired) in %d bytes to %s", len(serialized), discard, size, tmpFd.Name())
	serialized = nil
	return tmpFileName, nil
}

func ShutdownAllBuckets(buckets *Buckets) error {
	buckets.Bucket_map.Range(func(rkey, rvalue interface{}) bool {
		key := rkey.(string)
		val := rvalue.(*Leaky)
		val.tomb.Kill(nil)
		log.Infof("killed %s", key)
		return true
	})
	return nil
}

func PourItemToBucket(bucket *Leaky, holder BucketFactory, buckets *Buckets, parsed *types.Event) (bool, error) {
	var sent bool
	var buckey = bucket.Mapkey
	var err error

	sigclosed := 0
	failed_sent := 0
	attempts := 0
	start := time.Now().UTC()

	for !sent {
		attempts += 1
		/* Warn the user if we used more than a 100 ms to pour an event, it's at least an half lock*/
		if attempts%100000 == 0 && start.Add(100*time.Millisecond).Before(time.Now().UTC()) {
			holder.logger.Warningf("stuck for %s sending event to %s (sigclosed:%d failed_sent:%d attempts:%d)", time.Since(start),
				buckey, sigclosed, failed_sent, attempts)
		}

		/* check if leak routine is up */
		select {
		case _, ok := <-bucket.Signal:
			if !ok {
				//the bucket was found and dead, get a new one and continue
				bucket.logger.Tracef("Bucket %s found dead, cleanup the body", buckey)
				buckets.Bucket_map.Delete(buckey)
				sigclosed += 1
				bucket, err = LoadOrStoreBucketFromHolder(buckey, buckets, holder, parsed.ExpectMode)
				if err != nil {
					return false, err
				}
				continue
			}
			//holder.logger.Tracef("Signal exists, try to pour :)")
		default:
			/*nothing to read, but not closed, try to pour */
			//holder.logger.Tracef("Signal exists but empty, try to pour :)")
		}

		/*let's see if this time-bucket should have expired */
		if bucket.Mode == types.TIMEMACHINE {
			bucket.mutex.Lock()
			firstTs := bucket.First_ts
			lastTs := bucket.Last_ts
			bucket.mutex.Unlock()

			if !firstTs.IsZero() {
				var d time.Time
				err = d.UnmarshalText([]byte(parsed.MarshaledTime))
				if err != nil {
					holder.logger.Warningf("Failed unmarshaling event time (%s) : %v", parsed.MarshaledTime, err)
				}
				if d.After(lastTs.Add(bucket.Duration)) {
					bucket.logger.Tracef("bucket is expired (curr event: %s, bucket deadline: %s), kill", d, lastTs.Add(bucket.Duration))
					buckets.Bucket_map.Delete(buckey)
					//not sure about this, should we create a new one ?
					sigclosed += 1
					bucket, err = LoadOrStoreBucketFromHolder(buckey, buckets, holder, parsed.ExpectMode)
					if err != nil {
						return false, err
					}
					continue
				}
			}
		}
		/*the bucket seems to be up & running*/
		select {
		case bucket.In <- parsed:
			//holder.logger.Tracef("Successfully sent !")
			if BucketPourTrack {
				if _, ok := BucketPourCache[bucket.Name]; !ok {
					BucketPourCache[bucket.Name] = make([]types.Event, 0)
				}
				evt := deepcopy.Copy(*parsed)
				BucketPourCache[bucket.Name] = append(BucketPourCache[bucket.Name], evt.(types.Event))
			}
			sent = true
			continue
		default:
			failed_sent += 1
			//holder.logger.Tracef("Failed to send, try again")
			continue

		}
	}
	holder.logger.Debugf("bucket '%s' is poured", holder.Name)
	return sent, nil
}

func LoadOrStoreBucketFromHolder(partitionKey string, buckets *Buckets, holder BucketFactory, expectMode int) (*Leaky, error) {

	biface, ok := buckets.Bucket_map.Load(partitionKey)

	/* the bucket doesn't exist, create it !*/
	if !ok {
		var fresh_bucket *Leaky

		switch expectMode {
		case types.TIMEMACHINE:
			fresh_bucket = NewTimeMachine(holder)
			holder.logger.Debugf("Creating TimeMachine bucket")
		case types.LIVE:
			fresh_bucket = NewLeaky(holder)
			holder.logger.Debugf("Creating Live bucket")
		default:
			return nil, fmt.Errorf("input event has no expected mode : %+v", expectMode)
		}
		fresh_bucket.In = make(chan *types.Event)
		fresh_bucket.Mapkey = partitionKey
		fresh_bucket.Signal = make(chan bool, 1)
		actual, stored := buckets.Bucket_map.LoadOrStore(partitionKey, fresh_bucket)
		if !stored {
			holder.tomb.Go(func() error {
				return LeakRoutine(fresh_bucket)
			})
			biface = fresh_bucket
			//once the created goroutine is ready to process event, we can return it
			<-fresh_bucket.Signal
		} else {
			holder.logger.Debugf("Unexpectedly found exisint bucket for %s", partitionKey)
			biface = actual
		}
		holder.logger.Debugf("Created new bucket %s", partitionKey)
	}
	return biface.(*Leaky), nil
}

var orderEvent map[string]*sync.WaitGroup

func PourItemToHolders(parsed types.Event, holders []BucketFactory, buckets *Buckets) (bool, error) {
	var (
		ok, condition, poured bool
	)

	if BucketPourTrack {
		if BucketPourCache == nil {
			BucketPourCache = make(map[string][]types.Event)
		}
		if _, ok = BucketPourCache["OK"]; !ok {
			BucketPourCache["OK"] = make([]types.Event, 0)
		}
		evt := deepcopy.Copy(parsed)
		BucketPourCache["OK"] = append(BucketPourCache["OK"], evt.(types.Event))
	}
	//find the relevant holders (scenarios)
	for idx := 0; idx < len(holders); idx++ {
		//for idx, holder := range holders {

		//evaluate bucket's condition
		if holders[idx].RunTimeFilter != nil {
			holders[idx].logger.Tracef("event against holder %d/%d", idx, len(holders))
			output, err := exprhelpers.Run(holders[idx].RunTimeFilter,
				map[string]interface{}{"evt": &parsed},
				holders[idx].logger,
				holders[idx].Debug)
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

		//groupby determines the partition key for the specific bucket
		var groupby string
		if holders[idx].RunTimeGroupBy != nil {
			tmpGroupBy, err := exprhelpers.Run(holders[idx].RunTimeGroupBy, map[string]interface{}{"evt": &parsed}, holders[idx].logger, holders[idx].Debug)
			if err != nil {
				holders[idx].logger.Errorf("failed groupby : %v", err)
				return false, errors.New("leaky failed :/")
			}

			if groupby, ok = tmpGroupBy.(string); !ok {
				holders[idx].logger.Fatalf("failed groupby type : %v", err)
				return false, errors.New("groupby wrong type")
			}
		}
		buckey := GetKey(holders[idx], groupby)

		//we need to either find the existing bucket, or create a new one (if it's the first event to hit it for this partition key)
		bucket, err := LoadOrStoreBucketFromHolder(buckey, buckets, holders[idx], parsed.ExpectMode)
		if err != nil {
			return false, fmt.Errorf("failed to load or store bucket: %w", err)
		}
		//finally, pour the even into the bucket

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

		ok, err := PourItemToBucket(bucket, holders[idx], buckets, &parsed)

		if bucket.orderEvent {
			orderEvent[buckey].Wait()
		}

		if err != nil {
			return false, fmt.Errorf("failed to pour bucket: %w", err)
		}
		if ok {
			poured = true
		}
	}
	return poured, nil
}
