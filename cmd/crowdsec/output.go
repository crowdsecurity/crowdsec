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
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type alertBuffer struct {
	mu     sync.Mutex
	alerts []pipeline.RuntimeAlert
}

func (b *alertBuffer) add(a pipeline.RuntimeAlert) {
	b.mu.Lock()
	b.alerts = append(b.alerts, a)
	b.mu.Unlock()
}

func (b *alertBuffer) takeAll() []pipeline.RuntimeAlert {
	b.mu.Lock()
	batch := b.alerts
	b.alerts = nil
	b.mu.Unlock()
	return batch
}

func (b *alertBuffer) requeue(batch []pipeline.RuntimeAlert) {
	if len(batch) == 0 {
		return
	}
	b.mu.Lock()
	b.alerts = append(b.alerts, batch...)
	b.mu.Unlock()
}

func dedupAlerts(alerts []pipeline.RuntimeAlert) []*models.Alert {
	var dedupCache []*models.Alert

	for idx, alert := range alerts {
		log.Tracef("alert %d/%d", idx, len(alerts))
		if len(alert.Sources) <= 1 {
			dedupCache = append(dedupCache, alert.Alert)
			continue
		}

		// if we have more than one source, we need to dedup
		for k, src := range alert.Sources {
			log.Tracef("source[%s]", k)
			refsrc := *alert.Alert // copy
			refsrc.Source = &src
			dedupCache = append(dedupCache, &refsrc)
		}
	}

	if len(dedupCache) != len(alerts) {
		log.Tracef("went from %d to %d alerts", len(alerts), len(dedupCache))
	}

	return dedupCache
}

func PushAlerts(ctx context.Context, alerts []pipeline.RuntimeAlert, client *apiclient.ApiClient) error {
	alertsToPush := dedupAlerts(alerts)

	_, _, err := client.Alerts.Add(ctx, alertsToPush)
	if err != nil {
		return fmt.Errorf("failed sending alert to LAPI: %w", err)
	}

	return nil
}

func runOutput(
	ctx context.Context,
	input chan pipeline.Event,
	overflow chan pipeline.Event,
	bucketStore *leaky.BucketStore,
	postOverflowCTX parser.UnixParserCtx,
	postOverflowNodes []parser.Node,
	client *apiclient.ApiClient,
	sd *StateDumper,
) error {
	var pendingAlerts alertBuffer

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			batch := pendingAlerts.takeAll()
			if len(batch) == 0 {
				break
			}
			/*
				This loop needs to block as little as possible as scenarios directly write to the input chan
				Under high load, LAPI may take between 1 and 2 seconds to process ~100 alerts, which slows down everything including the WAF.
				Send the alerts from a goroutine to avoid staying too long in this case.
			*/
			outputsTomb.Go(func() error {
				if err := PushAlerts(ctx, batch, client); err != nil {
					log.Errorf("while pushing to api : %s", err)
					// just push back the events to the queue
					pendingAlerts.requeue(batch)
				}
				return nil
			})
		case <-outputsTomb.Dying():
			batch := pendingAlerts.takeAll()
			if len(batch) > 0 {
				if err := PushAlerts(ctx, batch, client); err != nil {
					log.Errorf("while pushing leftovers to api : %s", err)
				}
			}
			return nil
		case event := <-overflow:
			// if alert is empty and mapKey is present, the overflow is just to cleanup bucket
			if event.Overflow.Alert == nil && event.Overflow.Mapkey != "" {
				bucketStore.Delete(event.Overflow.Mapkey)
				break
			}

			/* process post overflow parser nodes */
			event, err := parser.Parse(postOverflowCTX, event, postOverflowNodes, sd.StageParse)
			if err != nil {
				return fmt.Errorf("postoverflow failed: %w", err)
			}

			ov := event.Overflow
			log.Info(*ov.Alert.Message)

			// if the Alert is nil, it's to signal bucket is ready for GC, don't track this
			// dump after postoveflow processing to avoid missing whitelist info
			if flags.DumpDir != "" && ov.Alert != nil {
				sd.BucketOverflows = append(sd.BucketOverflows, event)
			}

			if ov.Whitelisted {
				log.Infof("[%s] is whitelisted, skip.", *ov.Alert.Message)
				continue
			}

			if ov.Reprocess {
				select {
				case input <- event:
					log.Debug("Reprocessing overflow event")
				case <-ctx.Done():
					log.Debug("Reprocessing overflow event: parsing is dead, skipping")
				}
			}

			if flags.DumpDir != "" {
				continue
			}

			pendingAlerts.add(ov)
		}
	}
}
