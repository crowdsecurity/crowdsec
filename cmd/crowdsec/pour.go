package main

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func shouldTriggerGC(count int) bool {
	return count % 5000 == 0
}

func triggerGC(parsed pipeline.Event, buckets *leaky.Buckets, cConfig *csconfig.Config) error {
	log.Infof("%d existing buckets", leaky.LeakyRoutineCount)

	// when in forensics mode, garbage collect buckets
	if !cConfig.Crowdsec.BucketsGCEnabled || parsed.MarshaledTime == "" {
		return nil
	}

	z := &time.Time{}
	if err := z.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
		log.Warningf("Failed to parse time from event '%s': %s", parsed.MarshaledTime, err)
		return nil
	}

	log.Warning("Starting buckets garbage collection...")

	return leaky.GarbageCollectBuckets(*z, buckets)
}

func runPour(input chan pipeline.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets, cConfig *csconfig.Config) error {
	count := 0

	for {
		// bucket is now ready
		select {
		case <-bucketsTomb.Dying():
			log.Infof("Bucket routine exiting")
			return nil
		case parsed := <-input:
			startTime := time.Now()

			count++
			if shouldTriggerGC(count) {
				if err := triggerGC(parsed, buckets, cConfig); err != nil {
					return fmt.Errorf("failed to start bucket GC: %w", err)
				}
			}
			// here we can bucketify with parsed
			poured, err := leaky.PourItemToHolders(parsed, holders, buckets)
			if err != nil {
				log.Errorf("bucketify failed for: %v with %s", parsed, err)
				continue
			}

			elapsed := time.Since(startTime)
			metrics.GlobalPourHistogram.With(prometheus.Labels{"type": parsed.Line.Module, "source": parsed.Line.Src}).Observe(elapsed.Seconds())

			if poured {
				metrics.GlobalBucketPourOk.Inc()
			} else {
				metrics.GlobalBucketPourKo.Inc()
			}

			if parsed.MarshaledTime != "" {
				if err := lastProcessedItem.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
					log.Warningf("failed to parse time from event : %s", err)
				}
			}
		}
	}
}
