package main

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"

	"github.com/prometheus/client_golang/prometheus"
)

// Has to stay under the 3s ShutdownCrowdsecRoutines allows outputsTomb, or the
// final flush never runs.
const postOverflowDrainTimeout = 2 * time.Second

// Drops come in bursts, and the counter carries the exact number anyway.
const postOverflowDropWarnInterval = time.Minute

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

func handleOverflow(
	ctx context.Context,
	event pipeline.Event,
	input chan pipeline.Event,
	postOverflowCTX parser.UnixParserCtx,
	postOverflowNodes []parser.Node,
	sd *StateDumper,
	pendingAlerts *alertBuffer,
) {
	parsed, err := parser.Parse(postOverflowCTX, event, postOverflowNodes, sd.StageParse)
	if err != nil {
		scenario := ""
		if event.Overflow.Alert != nil && event.Overflow.Alert.Scenario != nil {
			scenario = *event.Overflow.Alert.Scenario
		}

		log.WithFields(log.Fields{
			"scenario":  scenario,
			"bucket_id": event.Overflow.BucketId,
			"sources":   event.Overflow.GetSources(),
		}).Errorf("postoverflow failed: %s", err)

		return
	}

	event = parsed
	ov := event.Overflow
	log.Info(*ov.Alert.Message)

	// if the Alert is nil, it's to signal bucket is ready for GC, don't track this
	// dump after postoveflow processing to avoid missing whitelist info
	// Appended without a lock, as before this ran in a worker: dump mode is
	// single-routine in practice, and output_routines > 1 already raced here.
	if flags.DumpDir != "" && ov.Alert != nil {
		sd.BucketOverflows = append(sd.BucketOverflows, event)
	}

	if ov.Whitelisted {
		log.Infof("[%s] is whitelisted, skip.", *ov.Alert.Message)
		return
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
		return
	}

	pendingAlerts.add(ov)
}

type overflowProcessor func(context.Context, pipeline.Event)

// Decouples the pipeline from postoverflow latency: parsing inline in outputLoop
// backpressured the whole engine, down to the appsec in-band responses (#4600).
func postOverflowWorker(ctx context.Context, queue chan pipeline.Event, process overflowProcessor) {
	for event := range queue {
		// the alerts we'd produce past this point have no one left to flush them
		select {
		case <-ctx.Done():
			return
		default:
		}

		process(ctx, event)
	}
}

// Warns on crossing 75% full, then on falling back under 25%: once we drop, it's
// too late to react. The gap between the two keeps a queue hovering at one
// threshold from logging on every tick.
func warnQueuePressure(depth int, size int, warned bool) bool {
	switch {
	case depth*4 >= size*3 && !warned:
		log.Warnf("postoverflow queue is %d/%d full, a postoverflow parser is slow (dns?): overflows will be dropped if it fills up", depth, size)
		return true
	case depth*4 < size && warned:
		log.Infof("postoverflow queue is draining, back under 25%% (%d/%d)", depth, size)
		return false
	}

	return warned
}

func runOutput(
	ctx context.Context,
	idx int,
	input chan pipeline.Event,
	overflow chan pipeline.Event,
	bucketStore *leaky.BucketStore,
	parsers *parser.Parsers,
	client *apiclient.ApiClient,
	sd *StateDumper,
	queueSize int,
) error {
	pendingAlerts := &alertBuffer{}

	process := func(ctx context.Context, event pipeline.Event) {
		handleOverflow(ctx, event, input, *parsers.PovfwCtx, parsers.Povfwnodes, sd, pendingAlerts)
	}

	return outputLoop(ctx, idx, overflow, bucketStore, process, client, pendingAlerts, queueSize, outputsTomb.Dying())
}

func outputLoop(
	ctx context.Context,
	idx int,
	overflow chan pipeline.Event,
	bucketStore *leaky.BucketStore,
	process overflowProcessor,
	client *apiclient.ApiClient,
	pendingAlerts *alertBuffer,
	queueSize int,
	dying <-chan struct{},
) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Dump mode (cscli explain, -dsn) parses inline: one-shot, and the dump stays ordered.
	inlinePostOverflow := flags.DumpDir != ""

	labels := prometheus.Labels{"routine": strconv.Itoa(idx)}
	queueDepth := metrics.GlobalPostOverflowQueueDepth.With(labels)
	dropCounter := metrics.GlobalPostOverflowDropped.With(labels)

	povfw := make(chan pipeline.Event, queueSize)
	workerDone := make(chan struct{})

	var (
		warnedPressure   bool
		droppedSinceWarn int
		lastDropWarn     time.Time
	)

	if !inlinePostOverflow {
		go func() {
			defer trace.ReportPanic()
			defer close(workerDone)
			postOverflowWorker(ctx, povfw, process)
		}()
	}

	for {
		select {
		case <-ticker.C:
			depth := len(povfw)
			queueDepth.Set(float64(depth))
			warnedPressure = warnQueuePressure(depth, queueSize, warnedPressure)

			if droppedSinceWarn > 0 && time.Since(lastDropWarn) >= postOverflowDropWarnInterval {
				log.Warnf("postoverflow queue full, dropped %d overflow(s) since the last warning", droppedSinceWarn)
				droppedSinceWarn = 0
				lastDropWarn = time.Now()
			}

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
		case <-dying:
			if !inlinePostOverflow {
				close(povfw)

				timer := time.NewTimer(postOverflowDrainTimeout)

				select {
				case <-workerDone:
				case <-timer.C:
					log.Warnf("timeout draining the postoverflow queue, %d overflow(s) lost", len(povfw))
				}

				timer.Stop()
			}

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

			if inlinePostOverflow {
				process(ctx, event)
				break
			}

			select {
			case povfw <- event:
			default:
				// Dropping is the fail-safe direction: postoverflow runs the
				// whitelists, so an unparsed alert would mean false positive bans.
				dropCounter.Inc()
				droppedSinceWarn++
			}
		}
	}
}
