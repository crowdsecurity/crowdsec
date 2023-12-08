package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func initCrowdsec(cConfig *csconfig.Config, hub *cwhub.Hub) (*parser.Parsers, error) {
	var err error

	if err = alertcontext.LoadConsoleContext(cConfig, hub); err != nil {
		return nil, fmt.Errorf("while loading context: %w", err)
	}

	// Start loading configs
	csParsers := parser.NewParsers(hub)
	if csParsers, err = parser.LoadParsers(cConfig, csParsers); err != nil {
		return nil, fmt.Errorf("while loading parsers: %w", err)
	}

	if err := LoadBuckets(cConfig, hub); err != nil {
		return nil, fmt.Errorf("while loading scenarios: %w", err)
	}

	if err := appsec.LoadAppsecRules(hub); err != nil {
		return nil, fmt.Errorf("while loading appsec rules: %w", err)
	}

	if err := LoadAcquisition(cConfig); err != nil {
		return nil, fmt.Errorf("while loading acquisition config: %w", err)
	}

	return csParsers, nil
}

func runCrowdsec(cConfig *csconfig.Config, parsers *parser.Parsers, hub *cwhub.Hub) error {
	inputEventChan = make(chan types.Event)
	inputLineChan = make(chan types.Event)

	//start go-routines for parsing, buckets pour and outputs.
	parserWg := &sync.WaitGroup{}
	parsersTomb.Go(func() error {
		parserWg.Add(1)
		for i := 0; i < cConfig.Crowdsec.ParserRoutinesCount; i++ {
			parsersTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runParse")
				if err := runParse(inputLineChan, inputEventChan, *parsers.Ctx, parsers.Nodes); err != nil { //this error will never happen as parser.Parse is not able to return errors
					log.Fatalf("starting parse error : %s", err)
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
		/*restore previous state as well if present*/
		if cConfig.Crowdsec.BucketStateFile != "" {
			log.Warningf("Restoring buckets state from %s", cConfig.Crowdsec.BucketStateFile)
			if err := leaky.LoadBucketsState(cConfig.Crowdsec.BucketStateFile, buckets, holders); err != nil {
				return fmt.Errorf("unable to restore buckets : %s", err)
			}
		}

		for i := 0; i < cConfig.Crowdsec.BucketsRoutinesCount; i++ {
			bucketsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runPour")
				if err := runPour(inputEventChan, holders, buckets, cConfig); err != nil {
					log.Fatalf("starting pour error : %s", err)
					return err
				}
				return nil
			})
		}
		bucketWg.Done()
		return nil
	})
	bucketWg.Wait()

	outputWg := &sync.WaitGroup{}
	outputsTomb.Go(func() error {
		outputWg.Add(1)
		for i := 0; i < cConfig.Crowdsec.OutputRoutinesCount; i++ {
			outputsTomb.Go(func() error {
				defer trace.CatchPanic("crowdsec/runOutput")
				if err := runOutput(inputEventChan, outputEventChan, buckets, *parsers.Povfwctx, parsers.Povfwnodes, *cConfig.API.Client.Credentials, hub); err != nil {
					log.Fatalf("starting outputs error : %s", err)
					return err
				}
				return nil
			})
		}
		outputWg.Done()
		return nil
	})
	outputWg.Wait()

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		aggregated := false
		if cConfig.Prometheus.Level == "aggregated" {
			aggregated = true
		}
		if err := acquisition.GetMetrics(dataSources, aggregated); err != nil {
			return fmt.Errorf("while fetching prometheus metrics for datasources: %w", err)
		}

	}
	log.Info("Starting processing data")

	if err := acquisition.StartAcquisition(dataSources, inputLineChan, &acquisTomb); err != nil {
		log.Fatalf("starting acquisition error : %s", err)
		return err
	}

	return nil
}

func serveCrowdsec(parsers *parser.Parsers, cConfig *csconfig.Config, hub *cwhub.Hub, agentReady chan bool) {
	crowdsecTomb.Go(func() error {
		defer trace.CatchPanic("crowdsec/serveCrowdsec")
		go func() {
			defer trace.CatchPanic("crowdsec/runCrowdsec")
			// this logs every time, even at config reload
			log.Debugf("running agent after %s ms", time.Since(crowdsecT0))
			agentReady <- true
			if err := runCrowdsec(cConfig, parsers, hub); err != nil {
				log.Fatalf("unable to start crowdsec routines: %s", err)
			}
		}()

		/*we should stop in two cases :
		- crowdsecTomb has been Killed() : it might be shutdown or reload, so stop
		- acquisTomb is dead, it means that we were in "cat" mode and files are done reading, quit
		*/
		waitOnTomb()
		log.Debugf("Shutting down crowdsec routines")
		if err := ShutdownCrowdsecRoutines(); err != nil {
			log.Fatalf("unable to shutdown crowdsec routines: %s", err)
		}
		log.Debugf("everything is dead, return crowdsecTomb")
		if dumpStates {
			dumpParserState()
			dumpOverflowState()
			dumpBucketsPour()
			os.Exit(0)
		}
		return nil
	})
}

func dumpBucketsPour() {
	fd, err := os.OpenFile(filepath.Join(parser.DumpFolder, "bucketpour-dump.yaml"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("open: %s", err)
	}
	out, err := yaml.Marshal(leaky.BucketPourCache)
	if err != nil {
		log.Fatalf("marshal: %s", err)
	}
	b, err := fd.Write(out)
	if err != nil {
		log.Fatalf("write: %s", err)
	}
	log.Tracef("wrote %d bytes", b)
	if err := fd.Close(); err != nil {
		log.Fatalf(" close: %s", err)
	}
}

func dumpParserState() {

	fd, err := os.OpenFile(filepath.Join(parser.DumpFolder, "parser-dump.yaml"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("open: %s", err)
	}
	out, err := yaml.Marshal(parser.StageParseCache)
	if err != nil {
		log.Fatalf("marshal: %s", err)
	}
	b, err := fd.Write(out)
	if err != nil {
		log.Fatalf("write: %s", err)
	}
	log.Tracef("wrote %d bytes", b)
	if err := fd.Close(); err != nil {
		log.Fatalf(" close: %s", err)
	}
}

func dumpOverflowState() {

	fd, err := os.OpenFile(filepath.Join(parser.DumpFolder, "bucket-dump.yaml"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("open: %s", err)
	}
	out, err := yaml.Marshal(bucketOverflows)
	if err != nil {
		log.Fatalf("marshal: %s", err)
	}
	b, err := fd.Write(out)
	if err != nil {
		log.Fatalf("write: %s", err)
	}
	log.Tracef("wrote %d bytes", b)
	if err := fd.Close(); err != nil {
		log.Fatalf(" close: %s", err)
	}
}

func waitOnTomb() {
	for {
		select {
		case <-acquisTomb.Dead():
			/*if it's acquisition dying it means that we were in "cat" mode.
			while shutting down, we need to give time for all buckets to process in flight data*/
			log.Warning("Acquisition is finished, shutting down")
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
