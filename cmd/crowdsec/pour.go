package main

import (
	"context"
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

func triggerGC(parsed pipeline.Event, buckets *leaky.Buckets, cConfig *csconfig.Config) {
	log.Infof("%d existing buckets", leaky.LeakyRoutineCount)
	// when in forensics mode, garbage collect buckets
	if !cConfig.Crowdsec.BucketsGCEnabled || parsed.MarshaledTime == "" {
		return
	}

	z := &time.Time{}
	if err := z.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
		log.Warningf("Failed to parse time from event '%s': %s", parsed.MarshaledTime, err)
		return
	}

	log.Warning("Starting buckets garbage collection ...")

	leaky.GarbageCollectBuckets(*z, buckets)
}

func runPour(ctx context.Context, input chan pipeline.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets, cConfig *csconfig.Config) {
	count := 0

	for {
		// bucket is now ready
		select {
		case <-ctx.Done():
			log.Info("Bucket routine exiting")
			return
		case parsed := <-input:
			startTime := time.Now()

			count++
			if shouldTriggerGC(count) {
				triggerGC(parsed, buckets, cConfig)
			}
			// here we can bucketify with parsed
			track := flags.DumpDir != ""
			poured, err := leaky.PourItemToHolders(ctx, parsed, holders, buckets, track)
			if err != nil {
				log.Warningf("bucketify failed for: %v with %s", parsed, err)
				continue
			}

			elapsed := time.Since(startTime)
			metrics.GlobalPourHistogram.With(prometheus.Labels{"type": parsed.Line.Module, "source": parsed.Line.Src}).Observe(elapsed.Seconds())

			if poured {
				metrics.GlobalBucketPourOk.Inc()
			} else {
				metrics.GlobalBucketPourKo.Inc()
			}
		}
	}
}
