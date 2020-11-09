package main

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
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
		return errors.Wrap(err, "failed to transform alerts for api")
	}
	_, _, err = client.Alerts.Add(ctx, alertsToPush)
	if err != nil {
		return errors.Wrap(err, "failed sending alert to LAPI")
	}
	return nil
}

func runOutput(input chan types.Event, overflow chan types.Event, buckets *leaky.Buckets,
	postOverflowCTX parser.UnixParserCtx, postOverflowNodes []parser.Node, apiConfig csconfig.ApiCredentialsCfg) error {

	var err error
	ticker := time.NewTicker(1 * time.Second)

	var cache []types.RuntimeAlert
	var cacheMutex sync.Mutex

	scenarios, err := cwhub.GetUpstreamInstalledScenariosAsString()
	if err != nil {
		return errors.Wrapf(err, "loading list of installed hub scenarios: %s", err)
	}

	apiURL, err := url.Parse(apiConfig.URL)
	if err != nil {
		return errors.Wrapf(err, "parsing api url ('%s'): %s", apiConfig.URL, err)
	}

	password := strfmt.Password(apiConfig.Password)

	Client, err := apiclient.NewClient(&apiclient.Config{
		MachineID:      apiConfig.Login,
		Password:       password,
		Scenarios:      scenarios,
		UserAgent:      fmt.Sprintf("crowdsec/%s", cwversion.VersionStr()),
		URL:            apiURL,
		VersionPrefix:  "v1",
		UpdateScenario: cwhub.GetUpstreamInstalledScenariosAsString,
	})
	if err != nil {
		return errors.Wrapf(err, "new client api: %s", err)
	}
	if _, err = Client.Auth.AuthenticateWatcher(context.Background(), models.WatcherAuthRequest{
		MachineID: &apiConfig.Login,
		Password:  &password,
		Scenarios: scenarios,
	}); err != nil {
		return errors.Wrapf(err, "authenticate watcher (%s)", apiConfig.Login)
	}

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
				}
			}
		case <-outputsTomb.Dying():
			if len(cache) > 0 {
				cacheMutex.Lock()
				cachecopy := cache
				newcache := make([]types.RuntimeAlert, 0)
				cache = newcache
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
			if event.Overflow.Reprocess {
				log.Debugf("Overflow being reprocessed.")
				input <- event
			}
			/* process post overflow parser nodes */
			event, err := parser.Parse(postOverflowCTX, event, postOverflowNodes)
			if err != nil {
				return fmt.Errorf("postoverflow failed : %s", err)
			}
			log.Printf("%s", *event.Overflow.Alert.Message)
			cacheMutex.Lock()
			cache = append(cache, event.Overflow)
			cacheMutex.Unlock()

		}
	}

	ticker.Stop()
	return nil

}
