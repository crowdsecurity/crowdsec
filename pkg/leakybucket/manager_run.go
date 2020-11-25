package leakybucket

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

var serialized map[string]Leaky

/*The leaky routines lifecycle are based on "real" time.
But when we are running in time-machine mode, the reference time is in logs and not "real" time.
Thus we need to garbage collect them to avoid a skyrocketing memory usage.*/
func GarbageCollectBuckets(deadline time.Time, buckets *Buckets) error {
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
			val.KillSwitch <- true
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
			val.KillSwitch <- true
			return true
		} else {
			val.logger.Tracef("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
		}
		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		} else {
			log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)
		}
		return true
	})
	log.Infof("Cleaned %d buckets", len(toflush))
	for _, flushkey := range toflush {
		buckets.Bucket_map.Delete(flushkey)
	}
	return nil
}

func DumpBucketsStateAt(deadline time.Time, outputdir string, buckets *Buckets) (string, error) {
	//var file string

	if outputdir == "" {
		return "", fmt.Errorf("empty output dir for dump bucket state")
	}
	tmpFd, err := ioutil.TempFile(os.TempDir(), "crowdsec-buckets-dump-")
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
		} else {
			val.logger.Debugf("(%s) not dead, count:%f capacity:%f", val.First_ts, tokat, tokcapa)
		}
		if _, ok := serialized[key]; ok {
			log.Errorf("entry %s already exists", key)
			return false
		} else {
			log.Debugf("serialize %s of %s : %s", val.Name, val.Uuid, val.Mapkey)
		}
		val.SerializedState = val.Limiter.Dump()
		serialized[key] = *val
		return true
	})
	bbuckets, err := json.MarshalIndent(serialized, "", " ")
	if err != nil {
		log.Fatalf("Failed to unmarshal buckets : %s", err)
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
		val.KillSwitch <- true
		log.Infof("killed %s", key)
		return true
	})
	return nil
}

func PourItemToHolders(parsed types.Event, holders []BucketFactory, buckets *Buckets) (bool, error) {
	var (
		ok, condition, sent bool
		err                 error
	)

	for idx, holder := range holders {

		if holder.RunTimeFilter != nil {
			holder.logger.Tracef("event against holder %d/%d", idx, len(holders))
			output, err := expr.Run(holder.RunTimeFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			if err != nil {
				holder.logger.Errorf("failed parsing : %v", err)
				return false, fmt.Errorf("leaky failed : %s", err)
			}
			// we assume we a bool should add type check here
			if condition, ok = output.(bool); !ok {
				holder.logger.Errorf("unexpected non-bool return : %T", output)
				holder.logger.Fatalf("Filter issue")
			}

			if holder.Debug {
				holder.ExprDebugger.Run(holder.logger, condition, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			}
			if !condition {
				holder.logger.Debugf("Event leaving node : ko (filter mismatch)")
				continue
			}
		}

		sent = false
		var groupby string
		if holder.RunTimeGroupBy != nil {
			tmpGroupBy, err := expr.Run(holder.RunTimeGroupBy, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &parsed}))
			if err != nil {
				holder.logger.Errorf("failed groupby : %v", err)
				return false, errors.New("leaky failed :/")
			}

			if groupby, ok = tmpGroupBy.(string); !ok {
				holder.logger.Fatalf("failed groupby type : %v", err)
				return false, errors.New("groupby wrong type")
			}
		}
		buckey := GetKey(holder, groupby)

		sigclosed := 0
		keymiss := 0
		failed_sent := 0
		attempts := 0
		start := time.Now()
		for !sent {
			attempts += 1
			/* Warn the user if we used more than a 100 ms to pour an event, it's at least an half lock*/
			if attempts%100000 == 0 && start.Add(100*time.Millisecond).Before(time.Now()) {
				holder.logger.Warningf("stuck for %s sending event to %s (sigclosed:%d keymiss:%d failed_sent:%d attempts:%d)", time.Since(start),
					buckey, sigclosed, keymiss, failed_sent, attempts)
			}
			biface, ok := buckets.Bucket_map.Load(buckey)
			//biface, bigout
			/* the bucket doesn't exist, create it !*/
			if !ok {
				/*
					not found in map
				*/

				holder.logger.Debugf("Creating bucket grouped by '%s'", groupby)
				keymiss++
				var fresh_bucket *Leaky

				switch parsed.ExpectMode {
				case TIMEMACHINE:
					fresh_bucket = NewTimeMachine(holder)
					holder.logger.Debugf("Creating TimeMachine bucket")
				case LIVE:
					fresh_bucket = NewLeaky(holder)
					holder.logger.Debugf("Creating Live bucket")
				default:
					holder.logger.Fatalf("input event has no expected mode, malformed : %+v", parsed)
				}
				fresh_bucket.GroupBy = groupby
				fresh_bucket.In = make(chan types.Event)
				fresh_bucket.Mapkey = buckey
				fresh_bucket.Signal = make(chan bool, 1)
				fresh_bucket.KillSwitch = make(chan bool, 1)
				buckets.Bucket_map.Store(buckey, fresh_bucket)
				go LeakRoutine(fresh_bucket)
				holder.logger.Debugf("Created new bucket %s", buckey)
				//wait for signal to be opened
				<-fresh_bucket.Signal
				continue
			}

			bucket := biface.(*Leaky)
			/* check if leak routine is up */
			select {
			case _, ok := <-bucket.Signal:
				if !ok {
					//it's closed, delete it
					bucket.logger.Debugf("Bucket %s found dead, cleanup the body", buckey)
					buckets.Bucket_map.Delete(buckey)
					sigclosed += 1
					continue
				}
				holder.logger.Tracef("Signal exists, try to pour :)")

			default:
				/*nothing to read, but not closed, try to pour */
				holder.logger.Tracef("Signal exists but empty, try to pour :)")

			}
			/*let's see if this time-bucket should have expired */
			if bucket.Mode == TIMEMACHINE && !bucket.First_ts.IsZero() {
				var d time.Time
				err = d.UnmarshalText([]byte(parsed.MarshaledTime))
				if err != nil {
					holder.logger.Warningf("Failed unmarshaling event time (%s) : %v", parsed.MarshaledTime, err)
				}
				if d.After(bucket.Last_ts.Add(bucket.Duration)) {
					bucket.logger.Tracef("bucket is expired (curr event: %s, bucket deadline: %s), kill", d, bucket.Last_ts.Add(bucket.Duration))
					buckets.Bucket_map.Delete(buckey)
					continue
				}
			}
			/*if we're here, let's try to pour */

			select {
			case bucket.In <- parsed:
				holder.logger.Tracef("Successfully sent !")
				//sent was successful !
				sent = true
				continue
			default:
				failed_sent += 1
				holder.logger.Tracef("Failed to send, try again")
				continue

			}
		}

		holder.logger.Debugf("bucket '%s' is poured", holder.Name)
	}
	return sent, nil
}
