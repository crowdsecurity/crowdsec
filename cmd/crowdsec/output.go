package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func runOutput(input chan types.Event, overflow chan types.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets,
	poctx parser.UnixParserCtx, ponodes []parser.Node) error {

LOOP:
	for {
		select {
		case <-outputsTomb.Dying():
			log.Infof("Flushing outputs")
			break LOOP
		case event := <-overflow:
			//if global simulation -> everything is simulation unless told otherwise
			if cConfig.Crowdsec.SimulationConfig != nil && cConfig.Crowdsec.SimulationConfig.Simulation {
				event.Overflow.Alert.Simulated = new(bool)
				*event.Overflow.Alert.Simulated = true

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
			if cConfig.Crowdsec.SimulationConfig != nil {
				for _, scenario_name := range cConfig.Crowdsec.SimulationConfig.Exclusions {
					if *event.Overflow.Alert.Scenario == scenario_name {
						*event.Overflow.Alert.Simulated = !*event.Overflow.Alert.Simulated

					}
				}
			}

			if event.Overflow.Alert.Scenario == nil && event.Overflow.Mapkey != "" {
				buckets.Bucket_map.Delete(event.Overflow.Mapkey)
			} else {
				log.Warningf("overflow : %+v", event)
			}
		}
	}
	return nil

}
