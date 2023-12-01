package main

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
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
		for k, src := range alert.Sources {
			refsrc := *alert.Alert //copy
			log.Tracef("source[%s]", k)
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

func runOutput(input chan types.Event, overflow chan types.Event, buckets *leaky.Buckets,
	postOverflowCTX parser.UnixParserCtx, postOverflowNodes []parser.Node,
	apiConfig csconfig.ApiCredentialsCfg, hub *cwhub.Hub) error {

	var err error
	ticker := time.NewTicker(1 * time.Second)

	var cache []types.RuntimeAlert
	var cacheMutex sync.Mutex

	scenarios, err := hub.GetInstalledItemNames(cwhub.SCENARIOS)
	if err != nil {
		return fmt.Errorf("loading list of installed hub scenarios: %w", err)
	}

	apiURL, err := url.Parse(apiConfig.URL)
	if err != nil {
		return fmt.Errorf("parsing api url ('%s'): %w", apiConfig.URL, err)
	}
	papiURL, err := url.Parse(apiConfig.PapiURL)
	if err != nil {
		return fmt.Errorf("parsing polling api url ('%s'): %w", apiConfig.PapiURL, err)
	}
	password := strfmt.Password(apiConfig.Password)

	Client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:      apiConfig.Login,
		Password:       password,
		Scenarios:      scenarios,
		UserAgent:      fmt.Sprintf("crowdsec/%s", version.String()),
		URL:            apiURL,
		PapiURL:        papiURL,
		VersionPrefix:  "v1",
		UpdateScenario: func() ([]string, error) {return hub.GetInstalledItemNames(cwhub.SCENARIOS)},
	})
	if err != nil {
		return fmt.Errorf("new client api: %w", err)
	}
	authResp, _, err := Client.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &apiConfig.Login,
		Password:  &password,
		Scenarios: scenarios,
	})
	if err != nil {
		return fmt.Errorf("authenticate watcher (%s): %w", apiConfig.Login, err)
	}

	if err := Client.GetClient().Transport.(*apiclient.JWTTransport).Expiration.UnmarshalText([]byte(authResp.Expire)); err != nil {
		return fmt.Errorf("unable to parse jwt expiration: %w", err)
	}

	Client.GetClient().Transport.(*apiclient.JWTTransport).Token = authResp.Token

	//start the heartbeat service
	log.Debugf("Starting HeartBeat service")
	Client.HeartBeat.StartHeartBeat(context.Background(), &outputsTomb)
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
				if err := PushAlerts(cachecopy, Client); err != nil {
					log.Errorf("while pushing to api : %s", err)
					//just push back the events to the queue
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
				if err := PushAlerts(cachecopy, Client); err != nil {
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
				return fmt.Errorf("postoverflow failed : %s", err)
			}
			log.Printf("%s", *event.Overflow.Alert.Message)
			//if the Alert is nil, it's to signal bucket is ready for GC, don't track this
			//dump after postoveflow processing to avoid missing whitelist info
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
