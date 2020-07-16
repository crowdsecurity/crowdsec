package main

import (
	"fmt"

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
		case <-outputsTomb.Dying():
			log.Infof("Flushing outputs")
			output.FlushAll()
			log.Debugf("Shuting down output routines")
			if err := output.Shutdown(); err != nil {
				log.Errorf("error while in output shutdown: %s", err)
			}
			log.Infof("Done shutdown down output")
			break LOOP
		case event := <-overflow:
			//if global simulation -> everything is simulation unless told otherwise
			if cConfig.SimulationCfg != nil && cConfig.SimulationCfg.Simulation {
				event.Overflow.Simulation = true
			}
			if cConfig.Profiling {
				start = time.Now()
			}

			if event.Overflow.Reprocess {
				log.Debugf("Overflow being reprocessed.")
				input <- event
			}

			/* process post overflow parser nodes */
			event, err := parser.Parse(poctx, event, ponodes)
			if err != nil {
				return fmt.Errorf("postoverflow failed : %s", err)
			}
			//check scenarios in simulation
			if cConfig.SimulationCfg != nil {
				for _, scenario_name := range cConfig.SimulationCfg.Exclusions {
					if event.Overflow.Scenario == scenario_name {
						event.Overflow.Simulation = !event.Overflow.Simulation
					}
				}
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
