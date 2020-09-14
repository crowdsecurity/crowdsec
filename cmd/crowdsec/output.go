package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func apiPushAlerts(alerts []types.RuntimeAlert, client *apiclient.ApiClient) error {
	ctx := context.Background()
	apialerts, err := apiDedupAlerts(alerts)

	if err != nil {
		return errors.Wrap(err, "failed to transform alerts for api")
	}
	resp, _, err := client.Alerts.Add(ctx, apialerts)
	if err != nil {
		return errors.Wrap(err, "failed sending alert to apil")
	}
	log.Printf("answer is %s", spew.Sdump(resp))
	return nil
}

func apiDedupAlerts(alerts []types.RuntimeAlert) ([]*models.Alert, error) {

	var dedup_cache []*models.Alert

	for idx, val := range alerts {
		log.Debugf("alert %d/%d", idx, len(alerts))
		/*if we have more than one source, we need to dedup */
		if len(val.Sources) == 0 || len(val.Sources) == 1 {
			dedup_cache = append(dedup_cache, val.Alert)
			continue
		}
		for k, src := range val.Sources {
			refsrc := *val.Alert //copy
			log.Debugf("source[%s]", k)
			refsrc.Source = &src
			dedup_cache = append(dedup_cache, &refsrc)
		}
	}
	if len(dedup_cache) != len(alerts) {
		log.Infof("went from %d to %d alerts", len(alerts), len(dedup_cache))
	}
	return dedup_cache, nil
}

func runOutput(input chan types.Event, overflow chan types.Event, holders []leaky.BucketFactory, buckets *leaky.Buckets,
	poctx parser.UnixParserCtx, ponodes []parser.Node) error {

	ticker := time.NewTicker(1 * time.Second)
	var cache []types.RuntimeAlert
	var cache_lock sync.Mutex

	log.Printf("API Client")
	t := &apiclient.JWTTransport{
		MachineID: "machine1",
		Password:  "machine1",
		Scenarios: []string{"aaaaaa", "bbbbb"},
	}
	Client := apiclient.NewClient(t.Client())

LOOP:
	for {
		select {
		case <-ticker.C:
			log.Printf("push time")
			if len(cache) > 0 {
				cache_lock.Lock()
				cachecopy := cache
				newcache := make([]types.RuntimeAlert, 0)
				cache = newcache
				if err := apiPushAlerts(cachecopy, Client); err != nil {
					log.Errorf("while pushing to api : %s", err)
				}
				cache_lock.Unlock()
			}
		case <-outputsTomb.Dying():
			log.Infof("Flushing outputs")
			break LOOP
		case event := <-overflow:
			//if global simulation -> everything is simulation unless told otherwise
			if cConfig.SimulationCfg != nil && cConfig.SimulationCfg.Simulation {
				event.Overflow.Alert.Simulated = true
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
					if event.Overflow.Alert.Scenario == scenario_name {
						event.Overflow.Alert.Simulated = !event.Overflow.Alert.Simulated
					}
				}
			}

			if event.Overflow.Alert.Scenario == "" && event.Overflow.Mapkey != "" {
				buckets.Bucket_map.Delete(event.Overflow.Mapkey)
			} else {
				cache_lock.Lock()
				cache = append(cache, event.Overflow)
				cache_lock.Unlock()
				log.Warningf("overflow : %+v", event)
			}
		}
	}

	ticker.Stop()
	return nil

}
