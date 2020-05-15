package main

import (
	log "github.com/sirupsen/logrus"

	"time"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runOutput(input chan types.Event, overflow chan types.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets,
	poctx parser.UnixParserCtx, ponodes []parser.Node, outputProfiles []types.Profile, output *outputs.Output) error {
	var (
		//action string
		start time.Time
	)

LOOP:
	for {
		select {
		case <-bucketsTomb.Dying():
			log.Infof("Exiting output processing")
			output.FlushAll()
			break LOOP
		case event := <-overflow:
			if cConfig.Profiling {
				start = time.Now()
			}

			if event.Overflow.Reprocess {
				log.Debugf("Overflow being reprocessed.")
				input <- event
			}

			if event.Overflow.Scenario == "" && event.Overflow.MapKey != "" {
				//log.Infof("Deleting expired entry %s", event.Overflow.MapKey)
				buckets.Bucket_map.Delete(event.Overflow.MapKey)
			} else {
				/*let's handle output profiles */
				if err := output.ProcessOutput(event.Overflow, outputProfiles); err != nil {
					log.Warningf("Error while processing overflow/output : %s", err)
				}
			}
		}
		if cConfig.Profiling {
			outputStat.AddTime(time.Since(start))
		}
	}
	return nil

}
