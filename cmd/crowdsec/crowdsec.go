package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
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

// runCrowdsec starts the log processor service
func runCrowdsec(cConfig *csconfig.Config, parsers *parser.Parsers, hub *cwhub.Hub, datasources []acquisition.DataSource) error {
	inputEventChan = make(chan types.Event)
	inputLineChan = make(chan types.Event)

	// start go-routines for parsing, buckets pour and outputs.
	parserWg := &sync.WaitGroup{}

	parsersTomb.Go(func() error {
		parserWg.Add(1)

		for range cConfig.Crowdsec.ParserRoutinesCount {
			parsersTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runParse")

				if err := runParse(inputLineChan, inputEventChan, *parsers.Ctx, parsers.Nodes); err != nil {
					// this error will never happen as parser.Parse is not able to return errors
					return err
				}

				return nil
			})
		}

		parserWg.Done()

		return nil
	})
	parserWg.Wait()

	bucketWg := &sync.WaitGroup{}

	bucketsTomb.Go(func() error {
		bucketWg.Add(1)
		// restore previous state as well if present
		if cConfig.Crowdsec.BucketStateFile != "" {
			log.Warningf("Restoring buckets state from %s", cConfig.Crowdsec.BucketStateFile)

			if err := leaky.LoadBucketsState(cConfig.Crowdsec.BucketStateFile, buckets, holders); err != nil {
				return fmt.Errorf("unable to restore buckets: %w", err)
			}
		}

		for range cConfig.Crowdsec.BucketsRoutinesCount {
			bucketsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runPour")

				return runPour(inputEventChan, holders, buckets, cConfig)
			})
		}

		bucketWg.Done()

		return nil
	})
	bucketWg.Wait()

	apiClient, err := apiclient.GetLAPIClient()
	if err != nil {
		return err
	}

	log.Debugf("Starting HeartBeat service")
	apiClient.HeartBeat.StartHeartBeat(context.Background(), &outputsTomb)

	outputWg := &sync.WaitGroup{}

	outputsTomb.Go(func() error {
		outputWg.Add(1)

		for range cConfig.Crowdsec.OutputRoutinesCount {
			outputsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runOutput")

				return runOutput(inputEventChan, outputEventChan, buckets, *parsers.Povfwctx, parsers.Povfwnodes, apiClient)
			})
		}

		outputWg.Done()

		return nil
	})
	outputWg.Wait()

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
		if cConfig.Prometheus.Level == configuration.CFG_METRICS_AGGREGATE {
			aggregated = true
		}

		if err := acquisition.GetMetrics(dataSources, aggregated); err != nil {
			return fmt.Errorf("while fetching prometheus metrics for datasources: %w", err)
		}
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
