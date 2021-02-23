package main

import (
	"fmt"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func initCrowdsec(cConfig *csconfig.GlobalConfig) (*parser.Parsers, error) {
	err := exprhelpers.Init()
	if err != nil {
		return &parser.Parsers{}, fmt.Errorf("Failed to init expr helpers : %s", err)
	}

	// Populate cwhub package tools
	if err := cwhub.GetHubIdx(cConfig.Cscli); err != nil {
		return &parser.Parsers{}, fmt.Errorf("Failed to load hub index : %s", err)
	}

	// Start loading configs
	csParsers := newParsers()
	if csParsers, err = parser.LoadParsers(cConfig, csParsers); err != nil {
		return &parser.Parsers{}, fmt.Errorf("Failed to load parsers: %s", err)
	}

	if err := LoadBuckets(cConfig); err != nil {
		return &parser.Parsers{}, fmt.Errorf("Failed to load scenarios: %s", err)
	}

	if err := LoadAcquisition(cConfig); err != nil {
		return &parser.Parsers{}, fmt.Errorf("Error while loading acquisition config : %s", err)
	}
	return csParsers, nil
}

func runCrowdsec(cConfig *csconfig.GlobalConfig, parsers *parser.Parsers) error {
	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	//start go-routines for parsing, buckets pour and ouputs.
	parserWg := &sync.WaitGroup{}
	parsersTomb.Go(func() error {
		parserWg.Add(1)
		for i := 0; i < cConfig.Crowdsec.ParserRoutinesCount; i++ {
			parsersTomb.Go(func() error {
				defer types.CatchPanic("crowdsec/runParse")
				err := runParse(inputLineChan, inputEventChan, *parsers.Ctx, parsers.Nodes)
				if err != nil { //this error will never happen as parser.Parse is not able to return errors
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
		/*restore as well previous state if present*/
		if cConfig.Crowdsec.BucketStateFile != "" {
			log.Warningf("Restoring buckets state from %s", cConfig.Crowdsec.BucketStateFile)
			if err := leaky.LoadBucketsState(cConfig.Crowdsec.BucketStateFile, buckets, holders); err != nil {
				return fmt.Errorf("unable to restore buckets : %s", err)
			}
		}

		for i := 0; i < cConfig.Crowdsec.BucketsRoutinesCount; i++ {
			bucketsTomb.Go(func() error {
				defer types.CatchPanic("crowdsec/runPour")
				err := runPour(inputEventChan, holders, buckets, cConfig)
				if err != nil {
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
				defer types.CatchPanic("crowdsec/runOutput")
				err := runOutput(inputEventChan, outputEventChan, buckets, *parsers.Povfwctx, parsers.Povfwnodes, *cConfig.API.Client.Credentials)
				if err != nil {
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
	log.Warningf("Starting processing data")

	if err := acquisition.StartAcquisition(dataSources, inputLineChan, &acquisTomb); err != nil {
		log.Fatalf("starting acquisition error : %s", err)
		return err
	}

	return nil
}

func serveCrowdsec(parsers *parser.Parsers, cConfig *csconfig.GlobalConfig) {
	crowdsecTomb.Go(func() error {
		defer types.CatchPanic("crowdsec/serveCrowdsec")
		go func() {
			defer types.CatchPanic("crowdsec/runCrowdsec")
			runCrowdsec(cConfig, parsers)
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
		return nil
	})
}

func waitOnTomb() {
	for {
		select {
		case <-acquisTomb.Dead():
			/*if it's acquisition dying it means that we were in "cat" mode.
			while shutting down, we need to give time for all buckets to process in flight data*/
			log.Warningf("Acquisition is finished, shutting down")
			/*
				While it might make sense to want to shut-down parser/buckets/etc. as soon as acquisition is finished,
				we might have some pending buckets : buckets that overflowed, but which LeakRoutine are still alive because they
				are waiting to be able to "commit" (push to api). This can happens specifically in a context where a lot of logs
				are going to trigger overflow (ie. trigger buckets with ~100% of the logs triggering an overflow).

				To avoid this (which would mean that we would "lose" some overflows), let's monitor the number of live buckets.
				However, because of the blackhole mechanism, you can't really wait for the number of LeakRoutine to go to zero (we might have to wait $blackhole_duration).

				So : we are waiting for the number of buckets to stop decreasing before returning. "how long" we should wait is a bit of the trick question,
				as some operations (ie. reverse dns or such in post-overflow) can take some time :)
			*/

			bucketsTomb.Kill(nil)
			bucketsTomb.Wait()
			return

		case <-crowdsecTomb.Dying():
			log.Infof("Crowdsec engine shutting down")
			return
		}
	}
}
