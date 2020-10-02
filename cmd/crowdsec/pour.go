package main

import (
	"fmt"
	"time"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func runPour(input chan types.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets) error {
	var (
		count int
	)
LOOP:
	for {
		//bucket is now ready
		select {
		case <-bucketsTomb.Dying():
			log.Infof("Exiting pour routine")

			break LOOP
		case parsed := <-input:
			count++
			if count%5000 == 0 {
				log.Warningf("%d existing LeakyRoutine", leaky.LeakyRoutineCount)
				//when in forensics mode, garbage collect buckets
				if cConfig.Crowdsec.BucketsGCEnabled {
					if parsed.MarshaledTime != "" {
						var z *time.Time = &time.Time{}
						if err := z.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
							log.Warningf("Failed to unmarshal time from event '%s' : %s", parsed.MarshaledTime, err)
						} else {
							log.Warningf("Starting buckets garbage collection ...")
							if err = leaky.GarbageCollectBuckets(*z, buckets); err != nil {
								return fmt.Errorf("failed to start bucket GC : %s", err)
							}
						}
					}
				}
			}
			//here we can bucketify with parsed
			poured, err := leaky.PourItemToHolders(parsed, holders, buckets)
			if err != nil {
				log.Fatalf("bucketify failed for: %v", parsed)
				return fmt.Errorf("process of event failed : %v", err)
			}
			if poured {
				globalBucketPourOk.Inc()
			} else {
				globalBucketPourKo.Inc()
			}
			if len(parsed.MarshaledTime) != 0 {
				if err := lastProcessedItem.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
					log.Warningf("failed to unmarshal time from event : %s", err)
				}
			}

		}
	}
	log.Tracef("Sending signal Bucketify")
	return nil
}
