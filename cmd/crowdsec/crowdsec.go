package main

import (
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/sevlyar/go-daemon"
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
			err := runParse(inputLineChan, inputEventChan, *parsers.ctx, parsers.nodes)
			if err != nil {
				log.Errorf("runParse error : %s", err)
				return err
			}
			return nil
		})
	}

	bucketsTomb.Go(func() error {
		err := runPour(inputEventChan, holders, buckets)
		if err != nil {
			log.Errorf("runPour error : %s", err)
			return err
		}
		return nil
	})

	outputsTomb.Go(func() error {
		err := runOutput(inputEventChan, outputEventChan, buckets, *parsers.povfwctx, parsers.povfwnodes, *cConfig.API.Client.Credentials)
		if err != nil {
			log.Errorf("runOutput error : %s", err)
			return err
		}
		return nil
	})
	log.Warningf("Starting processing data")

	if err := acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb); err != nil {
		return fmt.Errorf("While starting to read : %s", err)
	}

	return nil
}

func serveCrowdsec(daemonCTX daemon.Context) {
	crowdsecTomb.Go(func() error {
		go func() {
			if cConfig.Common != nil && !cConfig.Common.Daemonize {
				if err := serveOneTimeRun(); err != nil {
					log.Errorf(err.Error())
				}
			} else {
				defer daemonCTX.Release() //nolint:errcheck // won't bother checking this error in defer statement
				err := daemon.ServeSignals()
				if err != nil {
					log.Errorf("serveDaemon error : %s", err.Error())
				}
			}
		}()

		<-crowdsecTomb.Dying()
		if err := ShutdownCrowdsecRoutines(); err != nil {
			log.Fatalf("unable to shutdown crowdsec routines: %s", err)
		}
		return nil
	})
}
