package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// initCrowdsec prepares the log processor service
func initCrowdsec(ctx context.Context, cConfig *csconfig.Config, hub *cwhub.Hub, testMode bool) (*parser.Parsers, []acquisition.DataSource, error) {
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
			ctx, cConfig.API.Client.Credentials.URL, cConfig.API.Client.Credentials.PapiURL,
			cConfig.API.Client.Credentials.Login, cConfig.API.Client.Credentials.Password,
			hub.GetInstalledListForAPI())
		if err != nil {
			return nil, nil, fmt.Errorf("while initializing LAPIClient: %w", err)
		}
	}

	datasources, err := LoadAcquisition(ctx, cConfig, hub)
	if err != nil {
		return nil, nil, fmt.Errorf("while loading acquisition config: %w", err)
	}

	return csParsers, datasources, nil
}

func startParserRoutines(ctx context.Context, g *errgroup.Group, cConfig *csconfig.Config, parsers *parser.Parsers) {
	for idx := range cConfig.Crowdsec.ParserRoutinesCount {
		log.WithField("idx", idx).Info("Starting parser routine")
		g.Go(func() error {
			defer trace.CatchPanic("crowdsec/runParse/"+strconv.Itoa(idx))
			runParse(ctx, logLines, inEvents, *parsers.Ctx, parsers.Nodes)
			return nil
		})
	}
}

func startBucketRoutines(ctx context.Context, g *errgroup.Group, cConfig *csconfig.Config) {
	for idx := range cConfig.Crowdsec.BucketsRoutinesCount {
		log.WithField("idx", idx).Info("Starting bucket routine")
		g.Go(func() error {
			defer trace.CatchPanic("crowdsec/runPour/"+strconv.Itoa(idx))
			runPour(ctx, inEvents, holders, buckets, cConfig)
			return nil
		})
	}
}

func startHeartBeat(ctx context.Context, _ *csconfig.Config, apiClient *apiclient.ApiClient) {
	log.Debugf("Starting HeartBeat service")
	apiClient.HeartBeat.StartHeartBeat(ctx)
}

func startOutputRoutines(ctx context.Context, cConfig *csconfig.Config, parsers *parser.Parsers, apiClient *apiclient.ApiClient) {
	for idx := range cConfig.Crowdsec.OutputRoutinesCount {
		log.WithField("idx", idx).Info("Starting output routine")
		outputsTomb.Go(func() error {
			defer trace.CatchPanic("crowdsec/runOutput/"+strconv.Itoa(idx))
			return runOutput(ctx, inEvents, outEvents, buckets, *parsers.PovfwCtx, parsers.Povfwnodes, apiClient)
		})
	}
}

func startLPMetrics(ctx context.Context, cConfig *csconfig.Config, apiClient *apiclient.ApiClient, hub *cwhub.Hub, datasources []acquisition.DataSource) error {
	mp := NewMetricsProvider(
		apiClient,
		lpMetricsDefaultInterval,
		log.WithField("service", "lpmetrics"),
		datasources,
		hub,
	)

	go func() {
		mp.Run(ctx)
	}()

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
func runCrowdsec(ctx context.Context, g *errgroup.Group, cConfig *csconfig.Config, parsers *parser.Parsers, hub *cwhub.Hub, datasources []acquisition.DataSource) error {
	inEvents = make(chan pipeline.Event)
	logLines = make(chan pipeline.Event)

	startParserRoutines(ctx, g, cConfig, parsers)
	startBucketRoutines(ctx, g, cConfig)

	apiClient, err := apiclient.GetLAPIClient()
	if err != nil {
		return err
	}

	startHeartBeat(ctx, cConfig, apiClient)

	startOutputRoutines(ctx, cConfig, parsers, apiClient)

	if err := startLPMetrics(ctx, cConfig, apiClient, hub, datasources); err != nil {
		return err
	}

	log.Info("Starting processing data")

	if err := acquisition.StartAcquisition(ctx, dataSources, logLines, &acquisTomb); err != nil {
		return fmt.Errorf("starting acquisition error: %w", err)
	}

	return nil
}

// serveCrowdsec wraps the log processor service
func serveCrowdsec(ctx context.Context, parsers *parser.Parsers, cConfig *csconfig.Config, hub *cwhub.Hub, datasources []acquisition.DataSource, agentReady chan bool) {
	cctx, cancel := context.WithCancel(ctx)

	var g errgroup.Group

	crowdsecTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveCrowdsec")

		go func() {
			defer trace.CatchPanic("crowdsec/runCrowdsec")
			// this logs every time, even at config reload
			log.Debugf("running agent after %s ms", time.Since(crowdsecT0))

			agentReady <- true

			if err := runCrowdsec(cctx, &g, cConfig, parsers, hub, datasources); err != nil {
				log.Fatalf("unable to start crowdsec routines: %s", err)
			}
		}()

		/* we should stop in two cases :
		- crowdsecTomb has been Killed() : it might be shutdown or reload, so stop
		- acquisTomb is dead, it means that we were in "cat" mode and files are done reading, quit
		*/
		waitOnTomb()
		log.Debugf("Shutting down crowdsec routines")

		if err := ShutdownCrowdsecRoutines(cancel, &g); err != nil {
			return fmt.Errorf("unable to shutdown crowdsec routines: %w", err)
		}

		log.Debugf("everything is dead, return crowdsecTomb")

		if flags.DumpDir != "" {
			log.Debugf("Dumping parser+bucket states to %s", flags.DumpDir)

			if err := dumpAllStates(flags.DumpDir); err != nil {
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
