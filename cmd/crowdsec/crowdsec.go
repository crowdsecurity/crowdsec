package main

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
)

func initCrowdsec() (*parsers, error) {
	err := exprhelpers.Init()
	if err != nil {
		return &parsers{}, fmt.Errorf("Failed to init expr helpers : %s", err)
	}

	// Populate cwhub package tools
	if err := cwhub.GetHubIdx(cConfig.Cscli); err != nil {
		return &parsers{}, fmt.Errorf("Failed to load hub index : %s", err)
	}

	// Start loading configs
	csParsers := newParsers()
	if csParsers, err = LoadParsers(cConfig, csParsers); err != nil {
		return &parsers{}, fmt.Errorf("Failed to load parsers: %s", err)
	}

	if err := LoadBuckets(cConfig); err != nil {
		return &parsers{}, fmt.Errorf("Failed to load scenarios: %s", err)
	}

	if err := LoadAcquisition(cConfig); err != nil {
		return &parsers{}, fmt.Errorf("Error while loading acquisition config : %s", err)
	}
	return csParsers, nil
}

func runCrowdsec(parsers *parsers) error {
	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	//start go-routines for parsing, buckets pour and ouputs.
	for i := 0; i < cConfig.Crowdsec.ParserRoutinesCount; i++ {
		parsersTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/runParse")
			err := runParse(inputLineChan, inputEventChan, *parsers.ctx, parsers.nodes)
			if err != nil {
				log.Errorf("runParse error : %s", err)
				return err
			}
			return nil
		})
	}

	for i := 0; i < cConfig.Crowdsec.BucketsRoutinesCount; i++ {
		bucketsTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/runPour")
			err := runPour(inputEventChan, holders, buckets)
			if err != nil {
				log.Errorf("runPour error : %s", err)
				return err
			}
			return nil
		})
	}
	for i := 0; i < cConfig.Crowdsec.OutputRoutinesCount; i++ {

		outputsTomb.Go(func() error {
			defer types.CatchPanic("crowdsec/runOutput")
			err := runOutput(inputEventChan, outputEventChan, buckets, *parsers.povfwctx, parsers.povfwnodes, *cConfig.API.Client.Credentials)
			if err != nil {
				log.Errorf("runOutput error : %s", err)
				return err
			}
			return nil
		})
	}
	log.Warningf("Starting processing data")

	if err := acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb); err != nil {
		return fmt.Errorf("While starting to read : %s", err)
	}

	return nil
}

func serveCrowdsec(parsers *parsers) {
	crowdsecTomb.Go(func() error {
		defer types.CatchPanic("crowdsec/serveCrowdsec")
		go func() {
			defer types.CatchPanic("crowdsec/runCrowdsec")
			runCrowdsec(parsers)
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
			bucketCount := leaky.LeakyRoutineCount
			rounds := 0
			successiveStillRounds := 0
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
			for {
				currBucketCount := leaky.LeakyRoutineCount

				if currBucketCount == 0 {
					/*no bucket to wait on*/
					break
				}
				if currBucketCount != bucketCount {
					if rounds == 0 || rounds%2 == 0 {
						log.Printf("Still %d live LeakRoutines, waiting (was %d)", currBucketCount, bucketCount)
					}
					bucketCount = currBucketCount
					successiveStillRounds = 0
				} else {
					if successiveStillRounds > 1 {
						log.Printf("LeakRoutines commit over.")
						break
					}
					successiveStillRounds++
				}
				rounds++
				time.Sleep(5 * time.Second)
			}
			return
		case <-crowdsecTomb.Dying():
			log.Warningf("Crowdsec being killed, shutdown")
			return
		}
	}
}
