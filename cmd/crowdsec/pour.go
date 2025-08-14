package main

import (
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runPour(input chan types.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets, cConfig *csconfig.Config, stop <-chan struct{}, idleTimeout time.Duration) error {
	count := 0
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	lastActive := time.Now()
	idleTimer := time.NewTimer(idleTimeout)
	if !idleTimer.Stop() {
		select {
		case <-idleTimer.C:
		default:
		}
	}
	stopping := false

	for {
		// bucket is now ready
		select {
		case <-bucketsTomb.Dying():
			log.Infof("Bucket routine exiting")
			return nil
		case <-stop:
			stopping = true
			since := time.Since(lastActive)
			if since >= idleTimeout {
				return nil
			}
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleTimeout - since)
		case <-idleTimer.C:
			if stopping {
				return nil
			}
		case parsed := <-input:
			lastActive = time.Now()
			if stopping {
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(idleTimeout)
			}
			startTime := time.Now()

			count++
			if count%5000 == 0 {
				log.Infof("%d existing buckets", leaky.LeakyRoutineCount)
				// when in forensics mode, garbage collect buckets
				if cConfig.Crowdsec.BucketsGCEnabled {
					if parsed.MarshaledTime != "" {
						z := &time.Time{}
						if err := z.UnmarshalText([]byte(parsed.MarshaledTime)); err != nil {
							log.Warningf("Failed to parse time from event '%s' : %s", parsed.MarshaledTime, err)
						} else {
							log.Warning("Starting buckets garbage collection ...")

							if err = leaky.GarbageCollectBuckets(*z, buckets); err != nil {
								return fmt.Errorf("failed to start bucket GC : %w", err)
							}
						}
					}
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
