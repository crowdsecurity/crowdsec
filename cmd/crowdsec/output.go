package main

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/davecgh/go-spew/spew"
)

func dedupAlerts(alerts []types.RuntimeAlert) ([]*models.Alert, error) {

	var dedupCache []*models.Alert

	for idx, alert := range alerts {
		log.Debugf("alert %d/%d", idx, len(alerts))
		/*if we have more than one source, we need to dedup */
		if len(alert.Sources) == 0 || len(alert.Sources) == 1 {
			dedupCache = append(dedupCache, alert.Alert)
			continue
		}
		for k, src := range alert.Sources {
			refsrc := *alert.Alert //copy
			log.Debugf("source[%s]", k)
			refsrc.Source = &src
			dedupCache = append(dedupCache, &refsrc)
		}
	}
	if len(dedupCache) != len(alerts) {
		log.Infof("went from %d to %d alerts", len(alerts), len(dedupCache))
	}
	return dedupCache, nil
}

func PushAlerts(alerts []types.RuntimeAlert, client *apiclient.ApiClient) error {
	ctx := context.Background()
	alertsToPush, err := dedupAlerts(alerts)

	if err != nil {
		return errors.Wrap(err, "failed to transform alerts for api")
	}
	resp, _, err := client.Alerts.Add(ctx, alertsToPush)
	if err != nil {
		return errors.Wrap(err, "failed sending alert to apil")
	}
	log.Printf("answer is %s", spew.Sdump(resp))
	return nil
}

func runOutput(input chan types.Event, overflow chan types.Event, buckets *leaky.Buckets,
	postOverflowCTX parser.UnixParserCtx, postOverflowNodes []parser.Node, apiConfig csconfig.ApiCredentialsConfig) error {

	var err error
	ticker := time.NewTicker(1 * time.Second)

	var cache []types.RuntimeAlert
	var cacheMutex sync.Mutex

	apiclient.BaseURL, err = url.Parse(apiConfig.Url)
	if err != nil {
		return fmt.Errorf("unable to parse api url '%s': %s", apiConfig.Url, err)
	}
	password := strfmt.Password(apiConfig.Password)
	t := &apiclient.JWTTransport{
		MachineID: &apiConfig.Login,
		Password:  &password,
		Scenarios: []string{"aaaaaa", "bbbbb"},
	}
	Client := apiclient.NewClient(t.Client())

LOOP:
	for {
		select {
		case <-ticker.C:
			if len(cache) > 0 {
				cacheMutex.Lock()
				cachecopy := cache
				newcache := make([]types.RuntimeAlert, 0)
				cache = newcache
				if err := PushAlerts(cachecopy, Client); err != nil {
					log.Errorf("while pushing to api : %s", err)
				}
				cacheMutex.Unlock()
			}
		case <-outputsTomb.Dying():
			break LOOP
		case event := <-overflow:
			//if global simulation -> everything is simulation unless told otherwise
			if cConfig.Crowdsec.SimulationConfig.Simulation != nil && *cConfig.Crowdsec.SimulationConfig.Simulation {
				*event.Overflow.Alert.Simulated = true
			}

			if event.Overflow.Reprocess {
				log.Debugf("Overflow being reprocessed.")
				input <- event
			}

			/* process post overflow parser nodes */
			event, err := parser.Parse(postOverflowCTX, event, postOverflowNodes)
			if err != nil {
				return fmt.Errorf("postoverflow failed : %s", err)
			}
			//check scenarios in simulation
			if cConfig.Crowdsec.SimulationConfig != nil {
				for _, scenarioName := range cConfig.Crowdsec.SimulationConfig.Exclusions {
					if *event.Overflow.Alert.Scenario == scenarioName {
						result := *event.Overflow.Alert.Simulated
						*event.Overflow.Alert.Simulated = !result
					}
				}
			}

			if *event.Overflow.Alert.Scenario == "" && event.Overflow.Mapkey != "" {
				buckets.Bucket_map.Delete(event.Overflow.Mapkey)
			} else {
				cacheMutex.Lock()
				cache = append(cache, event.Overflow)
				cacheMutex.Unlock()
			}
		}
	}

	ticker.Stop()
	return nil

}
