package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// initCrowdsec prepares the log processor service
func initCrowdsec(cConfig *csconfig.Config, hub *cwhub.Hub, testMode bool) (*parser.Parsers, []acquisition.DataSource, error) {
	var err error

	if err = alertcontext.LoadConsoleContext(cConfig, hub); err != nil {
		return nil, nil, fmt.Errorf("while loading context: %w", err)
	}

	err = exprhelpers.GeoIPInit(hub.GetDataDir())
	if err != nil {
		// GeoIP databases are not mandatory, do not make crowdsec fail if they are not present
		log.Warnf("unable to initialize GeoIP: %s", err)
	}

	// Start loading configs
	csParsers := parser.NewParsers(hub)
	if csParsers, err = parser.LoadParsers(cConfig, csParsers); err != nil {
		return nil, nil, fmt.Errorf("while loading parsers: %w", err)
	}

	if err = LoadBuckets(cConfig, hub); err != nil {
		return nil, nil, fmt.Errorf("while loading scenarios: %w", err)
	}

	// can be nerfed by a build flag
	if err = LoadAppsecRules(hub); err != nil {
		return nil, nil, err
	}

	if !testMode {
		err = apiclient.InitLAPIClient(
			context.TODO(), cConfig.API.Client.Credentials.URL, cConfig.API.Client.Credentials.PapiURL,
			cConfig.API.Client.Credentials.Login, cConfig.API.Client.Credentials.Password,
			hub.GetInstalledListForAPI())
		if err != nil {
			return nil, nil, fmt.Errorf("while initializing LAPIClient: %w", err)
		}
	}

	datasources, err := LoadAcquisition(cConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("while loading acquisition config: %w", err)
	}

	return csParsers, datasources, nil
}

func startParserRoutines(cConfig *csconfig.Config, parsers *parser.Parsers) {
	// start go-routines for parsing, buckets pour and outputs.
	parserWg := &sync.WaitGroup{}

	// Determine initial worker count
	initialWorkers := cConfig.Crowdsec.ParserRoutinesCount
	if initialWorkers <= 0 {
		initialWorkers = 1
	}

	// Autoscale bounds
	minWorkers := initialWorkers
	maxWorkers := runtime.NumCPU()
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}

	// Feature-flagged autoscale; if disabled, keep fixed workers
	enableAutoscale := fflag.ParsersAutoscale.IsEnabled()

	parsersTomb.Go(func() error {
		parserWg.Add(1)

		// worker launcher with stop channel for downscale
		type workerRef struct{ stop chan struct{} }
		var workersMu sync.Mutex
		var workerRefs []workerRef
		launchWorker := func() {
			stop := make(chan struct{}, 1)
			workersMu.Lock()
			workerRefs = append(workerRefs, workerRef{stop: stop})
			workersMu.Unlock()
			parsersTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runParse")
				return runParse(inputLineChan, inputEventChan, *parsers.Ctx, parsers.Nodes, stop, 30*time.Second)
			})
		}

		// StagePool with downscale support via worker stop requests
		pool := NewStagePool(
			"parser",
			&parsersTomb,
			func() (int, int) { return len(inputLineChan), cap(inputLineChan) },
			minWorkers,
			maxWorkers,
			launchWorker,
			log.WithField("stage", "parser"),
		)
		pool.requestStop = func() bool {
			workersMu.Lock()
			defer workersMu.Unlock()
			if len(workerRefs) <= minWorkers {
				return false
			}
			// signal the last worker to stop; runParse will exit on idle
			ref := workerRefs[len(workerRefs)-1]
			select {
			case ref.stop <- struct{}{}:
				workerRefs = workerRefs[:len(workerRefs)-1]
				return true
			default:
				return false
			}
		}
		pool.Start(initialWorkers, enableAutoscale)

		parserWg.Done()
		return nil
	})
	parserWg.Wait()
}

func startBucketRoutines(cConfig *csconfig.Config) {
	bucketWg := &sync.WaitGroup{}

	// Determine initial worker count
	initialWorkers := cConfig.Crowdsec.BucketsRoutinesCount
	if initialWorkers <= 0 {
		initialWorkers = 1
	}

	// Autoscale bounds
	minWorkers := initialWorkers
	maxWorkers := runtime.NumCPU()
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}

	// Dedicated flag for buckets autoscale
	enableAutoscale := fflag.BucketsAutoscale.IsEnabled()

	bucketsTomb.Go(func() error {
		bucketWg.Add(1)

		// worker launcher with stop channel for downscale
		type workerRef struct{ stop chan struct{} }
		var workersMu sync.Mutex
		var workerRefs []workerRef
		launchWorker := func() {
			stop := make(chan struct{}, 1)
			workersMu.Lock()
			workerRefs = append(workerRefs, workerRef{stop: stop})
			workersMu.Unlock()
			bucketsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runPour")
				return runPour(inputEventChan, holders, buckets, cConfig, stop, 30*time.Second)
			})
		}

		pool := NewStagePool(
			"buckets",
			&bucketsTomb,
			func() (int, int) { return len(inputEventChan), cap(inputEventChan) },
			minWorkers,
			maxWorkers,
			launchWorker,
			log.WithField("stage", "buckets"),
		)
		pool.requestStop = func() bool {
			workersMu.Lock()
			defer workersMu.Unlock()
			if len(workerRefs) <= minWorkers {
				return false
			}
			ref := workerRefs[len(workerRefs)-1]
			select {
			case ref.stop <- struct{}{}:
				workerRefs = workerRefs[:len(workerRefs)-1]
				return true
			default:
				return false
			}
		}

		pool.Start(initialWorkers, enableAutoscale)

		bucketWg.Done()

		return nil
	})
	bucketWg.Wait()
}

func startHeartBeat(cConfig *csconfig.Config, apiClient *apiclient.ApiClient) {
	log.Debugf("Starting HeartBeat service")
	apiClient.HeartBeat.StartHeartBeat(context.Background(), &outputsTomb)
}

func startOutputRoutines(cConfig *csconfig.Config, parsers *parser.Parsers, apiClient *apiclient.ApiClient) {
	outputWg := &sync.WaitGroup{}

	// Determine initial worker count
	initialWorkers := cConfig.Crowdsec.OutputRoutinesCount
	if initialWorkers <= 0 {
		initialWorkers = 1
	}

	// Autoscale bounds
	minWorkers := initialWorkers
	maxWorkers := runtime.NumCPU()
	if maxWorkers < minWorkers {
		maxWorkers = minWorkers
	}

	enableAutoscale := fflag.OutputsAutoscale.IsEnabled()

	outputsTomb.Go(func() error {
		outputWg.Add(1)

		// worker launcher with stop channel for downscale
		type workerRef struct{ stop chan struct{} }
		var workersMu sync.Mutex
		var workerRefs []workerRef
		launchWorker := func() {
			stop := make(chan struct{}, 1)
			workersMu.Lock()
			workerRefs = append(workerRefs, workerRef{stop: stop})
			workersMu.Unlock()
			outputsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runOutput")
				return runOutput(inputEventChan, outputEventChan, buckets, *parsers.PovfwCtx, parsers.Povfwnodes, apiClient, stop, 30*time.Second)
			})
		}

		pool := NewStagePool(
			"outputs",
			&outputsTomb,
			func() (int, int) { return len(outputEventChan), cap(outputEventChan) },
			minWorkers,
			maxWorkers,
			launchWorker,
			log.WithField("stage", "outputs"),
		)
		pool.requestStop = func() bool {
			workersMu.Lock()
			defer workersMu.Unlock()
			if len(workerRefs) <= minWorkers {
				return false
			}
			ref := workerRefs[len(workerRefs)-1]
			select {
			case ref.stop <- struct{}{}:
				workerRefs = workerRefs[:len(workerRefs)-1]
				return true
			default:
				return false
			}
		}

		pool.Start(initialWorkers, enableAutoscale)

		outputWg.Done()

		return nil
	})
	outputWg.Wait()
}

func startLPMetrics(cConfig *csconfig.Config, apiClient *apiclient.ApiClient, hub *cwhub.Hub, datasources []acquisition.DataSource) error {
	mp := NewMetricsProvider(
		apiClient,
		lpMetricsDefaultInterval,
		log.WithField("service", "lpmetrics"),
		[]string{},
		datasources,
		hub,
	)

	lpMetricsTomb.Go(func() error {
		return mp.Run(context.Background(), &lpMetricsTomb)
	})

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		aggregated := false
		if cConfig.Prometheus.Level == metrics.MetricsLevelAggregated {
			aggregated = true
		}

		if err := acquisition.GetMetrics(dataSources, aggregated); err != nil {
			return fmt.Errorf("while fetching prometheus metrics for datasources: %w", err)
		}
	}

	return nil
}

// runCrowdsec starts the log processor service
func runCrowdsec(cConfig *csconfig.Config, parsers *parser.Parsers, hub *cwhub.Hub, datasources []acquisition.DataSource) error {
	// Buffer channels to reduce context switches and backpressure between stages.
	// Size them relative to the number of worker routines in the next stage.
	parserBufSize := cConfig.Crowdsec.ParserRoutinesCount * 4
	if parserBufSize < 1 {
		parserBufSize = 1
	}
	bucketBufSize := cConfig.Crowdsec.BucketsRoutinesCount * 4
	if bucketBufSize < 1 {
		bucketBufSize = 1
	}

	inputEventChan = make(chan types.Event, bucketBufSize)
	inputLineChan = make(chan types.Event, parserBufSize)

	startParserRoutines(cConfig, parsers)

	startBucketRoutines(cConfig)

	apiClient, err := apiclient.GetLAPIClient()
	if err != nil {
		return err
	}

	startHeartBeat(cConfig, apiClient)

	startOutputRoutines(cConfig, parsers, apiClient)

	if err := startLPMetrics(cConfig, apiClient, hub, datasources); err != nil {
		return err
	}

	log.Info("Starting processing data")

	if err := acquisition.StartAcquisition(context.TODO(), dataSources, inputLineChan, &acquisTomb); err != nil {
		return fmt.Errorf("starting acquisition error: %w", err)
	}

	return nil
}

// serveCrowdsec wraps the log processor service
func serveCrowdsec(parsers *parser.Parsers, cConfig *csconfig.Config, hub *cwhub.Hub, datasources []acquisition.DataSource, agentReady chan bool) {
	crowdsecTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveCrowdsec")

		go func() {
			defer trace.CatchPanic("crowdsec/runCrowdsec")
			// this logs every time, even at config reload
			log.Debugf("running agent after %s ms", time.Since(crowdsecT0))
			agentReady <- true

			if err := runCrowdsec(cConfig, parsers, hub, datasources); err != nil {
				log.Fatalf("unable to start crowdsec routines: %s", err)
			}
		}()

		/* we should stop in two cases :
		- crowdsecTomb has been Killed() : it might be shutdown or reload, so stop
		- acquisTomb is dead, it means that we were in "cat" mode and files are done reading, quit
		*/
		waitOnTomb()
		log.Debugf("Shutting down crowdsec routines")

		if err := ShutdownCrowdsecRoutines(); err != nil {
			return fmt.Errorf("unable to shutdown crowdsec routines: %w", err)
		}

		log.Debugf("everything is dead, return crowdsecTomb")

		if dumpStates {
			if err := dumpAllStates(); err != nil {
				log.Fatal(err)
			}
			os.Exit(0)
		}

		return nil
	})
}

func waitOnTomb() {
	for {
		select {
		case <-acquisTomb.Dead():
			/* if it's acquisition dying it means that we were in "cat" mode.
			while shutting down, we need to give time for all buckets to process in flight data*/
			log.Info("Acquisition is finished, shutting down")
			/*
				While it might make sense to want to shut-down parser/buckets/etc. as soon as acquisition is finished,
				we might have some pending buckets: buckets that overflowed, but whose LeakRoutine are still alive because they
				are waiting to be able to "commit" (push to api). This can happen specifically in a context where a lot of logs
				are going to trigger overflow (ie. trigger buckets with ~100% of the logs triggering an overflow).

				To avoid this (which would mean that we would "lose" some overflows), let's monitor the number of live buckets.
				However, because of the blackhole mechanism, we can't really wait for the number of LeakRoutine to go to zero
				(we might have to wait $blackhole_duration).

				So: we are waiting for the number of buckets to stop decreasing before returning. "how long" we should wait
				is a bit of the trick question, as some operations (ie. reverse dns or such in post-overflow) can take some time :)
			*/

			return

		case <-crowdsecTomb.Dying():
			log.Infof("Crowdsec engine shutting down")
			return
		}
	}
}
