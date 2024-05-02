package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func dedupAlerts(alerts []types.RuntimeAlert) ([]*models.Alert, error) {
	var dedupCache []*models.Alert

	for idx, alert := range alerts {
		log.Tracef("alert %d/%d", idx, len(alerts))
		/*if we have more than one source, we need to dedup */
		if len(alert.Sources) == 0 || len(alert.Sources) == 1 {
			dedupCache = append(dedupCache, alert.Alert)
			continue
		}

		for k := range alert.Sources {
			refsrc := *alert.Alert // copy

			log.Tracef("source[%s]", k)

			src := alert.Sources[k]
			refsrc.Source = &src
			dedupCache = append(dedupCache, &refsrc)
		}
	}

	if len(dedupCache) != len(alerts) {
		log.Tracef("went from %d to %d alerts", len(alerts), len(dedupCache))
	}

	return dedupCache, nil
}

func PushAlerts(alerts []types.RuntimeAlert, client *apiclient.ApiClient) error {
	ctx := context.Background()

	alertsToPush, err := dedupAlerts(alerts)
	if err != nil {
		return fmt.Errorf("failed to transform alerts for api: %w", err)
	}

	_, _, err = client.Alerts.Add(ctx, alertsToPush)
	if err != nil {
		return fmt.Errorf("failed sending alert to LAPI: %w", err)
	}

	return nil
}

var bucketOverflows []types.Event

func runOutput(input chan types.Event, overflow chan types.Event, buckets *leaky.Buckets, postOverflowCTX parser.UnixParserCtx,
	postOverflowNodes []parser.Node, client *apiclient.ApiClient) error {
	var (
		cache      []types.RuntimeAlert
		cacheMutex sync.Mutex
	)

	ticker := time.NewTicker(1 * time.Second)
LOOP:
	for {
		select {
		case <-ticker.C:
			if len(cache) > 0 {
				cacheMutex.Lock()
				cachecopy := cache
				newcache := make([]types.RuntimeAlert, 0)
				cache = newcache
				cacheMutex.Unlock()
				if err := PushAlerts(cachecopy, client); err != nil {
					log.Errorf("while pushing to api : %s", err)
					// just push back the events to the queue
					cacheMutex.Lock()
					cache = append(cache, cachecopy...)
					cacheMutex.Unlock()
				}
			}
		case <-outputsTomb.Dying():
			if len(cache) > 0 {
				cacheMutex.Lock()
				cachecopy := cache
				cacheMutex.Unlock()
				if err := PushAlerts(cachecopy, client); err != nil {
					log.Errorf("while pushing leftovers to api : %s", err)
				}
			}

			break LOOP
		case event := <-overflow:
			/*if alert is empty and mapKey is present, the overflow is just to cleanup bucket*/
			if event.Overflow.Alert == nil && event.Overflow.Mapkey != "" {
				buckets.Bucket_map.Delete(event.Overflow.Mapkey)
				break
			}
			/* process post overflow parser nodes */
			event, err := parser.Parse(postOverflowCTX, event, postOverflowNodes)
			if err != nil {
				return fmt.Errorf("postoverflow failed: %w", err)
			}
			log.Printf("%s", *event.Overflow.Alert.Message)
			// if the Alert is nil, it's to signal bucket is ready for GC, don't track this
			// dump after postoveflow processing to avoid missing whitelist info
			if dumpStates && event.Overflow.Alert != nil {
				if bucketOverflows == nil {
					bucketOverflows = make([]types.Event, 0)
				}
				bucketOverflows = append(bucketOverflows, event)
			}
			if event.Overflow.Whitelisted {
				log.Printf("[%s] is whitelisted, skip.", *event.Overflow.Alert.Message)
				continue
			}
			if event.Overflow.Reprocess {
				log.Debugf("Overflow being reprocessed.")
				input <- event
			}
			if dumpStates {
				continue
			}

			cacheMutex.Lock()
			cache = append(cache, event.Overflow)
			cacheMutex.Unlock()
		}
	}

	ticker.Stop()

	return nil
}
