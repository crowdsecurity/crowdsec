package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/pkg/trace"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

//nolint:deadcode,unused // debugHandler is kept as a dev convenience: it shuts down and serialize internal state
func debugHandler(sig os.Signal, cConfig *csconfig.Config) error {
	var (
		tmpFile string
		err     error
	)

	// stop goroutines
	if err = ShutdownCrowdsecRoutines(); err != nil {
		log.Warningf("Failed to shut down routines: %s", err)
	}

	// todo: properly stop acquis with the tail readers
	if tmpFile, err = leaky.DumpBucketsStateAt(time.Now().UTC(), cConfig.Crowdsec.BucketStateDumpDir, buckets); err != nil {
		log.Warningf("Failed to dump bucket state : %s", err)
	}

	if err := leaky.ShutdownAllBuckets(buckets); err != nil {
		log.Warningf("Failed to shut down routines : %s", err)
	}
	log.Printf("Shutdown is finished, buckets are in %s", tmpFile)
	return nil
}

func reloadHandler(sig os.Signal) (*csconfig.Config, error) {
	var tmpFile string

	// re-initialize tombs
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}
	pluginTomb = tomb.Tomb{}

	cConfig, err := LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false)
	if err != nil {
		return nil, err
	}

	if !cConfig.DisableAPI {
		if flags.DisableCAPI {
			log.Warningf("Communication with CrowdSec Central API disabled from args")
			cConfig.API.Server.OnlineClient = nil
		}
		apiServer, err := initAPIServer(cConfig)
		if err != nil {
			return nil, errors.Wrap(err, "unable to init api server")
		}

		apiReady := make(chan bool, 1)
		serveAPIServer(apiServer, apiReady)
	}

	if !cConfig.DisableAgent {
		csParsers, err := initCrowdsec(cConfig)
		if err != nil {
			return nil, errors.Wrap(err, "unable to init crowdsec")
		}

		// restore bucket state
		if tmpFile != "" {
			log.Warningf("we are now using %s as a state file", tmpFile)
			cConfig.Crowdsec.BucketStateFile = tmpFile
		}

		// reload the simulation state
		if err := cConfig.LoadSimulation(); err != nil {
			log.Errorf("reload error (simulation) : %s", err)
		}

		agentReady := make(chan bool, 1)
		serveCrowdsec(csParsers, cConfig, agentReady)
	}

	log.Printf("Reload is finished")
	// delete the tmp file, it's safe now :)
	if tmpFile != "" {
		if err := os.Remove(tmpFile); err != nil {
			log.Warningf("Failed to delete temp file (%s) : %s", tmpFile, err)
		}
	}
	return cConfig, nil
}

func ShutdownCrowdsecRoutines() error {
	var reterr error

	log.Debugf("Shutting down crowdsec sub-routines")
	if len(dataSources) > 0 {
		acquisTomb.Kill(nil)
		log.Debugf("waiting for acquisition to finish")
		drainChan(inputLineChan)
		if err := acquisTomb.Wait(); err != nil {
			log.Warningf("Acquisition returned error : %s", err)
			reterr = err
		}
	}

	log.Debugf("acquisition is finished, wait for parser/bucket/ouputs.")
	parsersTomb.Kill(nil)
	drainChan(inputEventChan)
	if err := parsersTomb.Wait(); err != nil {
		log.Warningf("Parsers returned error : %s", err)
		reterr = err
	}

	log.Debugf("parsers is done")
	time.Sleep(1 * time.Second) // ugly workaround for now to ensure PourItemtoholders are finished
	bucketsTomb.Kill(nil)

	if err := bucketsTomb.Wait(); err != nil {
		log.Warningf("Buckets returned error : %s", err)
		reterr = err
	}

	log.Debugf("buckets is done")
	time.Sleep(1 * time.Second) // ugly workaround for now
	outputsTomb.Kill(nil)

	if err := outputsTomb.Wait(); err != nil {
		log.Warningf("Ouputs returned error : %s", err)
		reterr = err
	}

	log.Debugf("outputs are done")
	// He's dead, Jim.
	crowdsecTomb.Kill(nil)

	return reterr
}

func shutdownAPI() error {
	log.Debugf("shutting down api via Tomb")
	apiTomb.Kill(nil)

	if err := apiTomb.Wait(); err != nil {
		return err
	}

	log.Debugf("done")
	return nil
}

func shutdownCrowdsec() error {
	log.Debugf("shutting down crowdsec via Tomb")
	crowdsecTomb.Kill(nil)

	if err := crowdsecTomb.Wait(); err != nil {
		return err
	}

	log.Debugf("done")
	return nil
}

func shutdown(sig os.Signal, cConfig *csconfig.Config) error {
	if !cConfig.DisableAgent {
		if err := shutdownCrowdsec(); err != nil {
			return errors.Wrap(err, "failed to shut down crowdsec")
		}
	}

	if !cConfig.DisableAPI {
		if err := shutdownAPI(); err != nil {
			return errors.Wrap(err, "failed to shut down api routines")
		}
	}

	return nil
}

func drainChan(c chan types.Event) {
	time.Sleep(500 * time.Millisecond)
	// delay to avoid draining chan before the acquisition/parser
	// get a chance to push its event
	// We should close the chan on the writer side rather than this
	for {
		select {
		case _, ok := <-c:
			if !ok { //closed
				return
			}
		default:
			return
		}
	}
}

func HandleSignals(cConfig *csconfig.Config) error {
	var (
		newConfig *csconfig.Config
		err       error
	)

	signalChan := make(chan os.Signal, 1)

	// We add os.Interrupt mostly to ease windows development,
	// it allows to simulate a clean shutdown when running in the console
	signal.Notify(signalChan,
		syscall.SIGHUP,
		syscall.SIGTERM,
		os.Interrupt)

	exitChan := make(chan error)

	go func() {
		defer trace.CatchPanic("crowdsec/HandleSignals")
	Loop:
		for {
			s := <-signalChan
			switch s {
			// kill -SIGHUP XXXX
			case syscall.SIGHUP:
				log.Warning("SIGHUP received, reloading")

				if err = shutdown(s, cConfig); err != nil {
					exitChan <- errors.Wrap(err, "failed shutdown")

					break Loop
				}

				if newConfig, err = reloadHandler(s); err != nil {
					exitChan <- errors.Wrap(err, "reload handler failure")

					break Loop
				}

				if newConfig != nil {
					cConfig = newConfig
				}
			// ctrl+C, kill -SIGINT XXXX, kill -SIGTERM XXXX
			case os.Interrupt, syscall.SIGTERM:
				log.Warning("SIGTERM received, shutting down")
				if err = shutdown(s, cConfig); err != nil {
					exitChan <- errors.Wrap(err, "failed shutdown")

					break Loop
				}
				exitChan <- nil
			}
		}
	}()

	err = <-exitChan
	if err == nil {
		log.Warning("Crowdsec service shutting down")
	}
	return err
}

func Serve(cConfig *csconfig.Config, apiReady chan bool, agentReady chan bool) error {
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}
	pluginTomb = tomb.Tomb{}

	if cConfig.API.Server != nil && cConfig.API.Server.DbConfig != nil {
		dbClient, err := database.NewClient(cConfig.API.Server.DbConfig)
		if err != nil {
			return errors.Wrap(err, "failed to get database client")
		}

		err = exprhelpers.Init(dbClient)
		if err != nil {
			return errors.Wrap(err, "failed to init expr helpers")
		}
	} else {
		err := exprhelpers.Init(nil)
		if err != nil {
			return errors.Wrap(err, "failed to init expr helpers")
		}

		log.Warningln("Exprhelpers loaded without database client.")
	}

	if cConfig.API.CTI != nil && *cConfig.API.CTI.Enabled {
		log.Infof("Crowdsec CTI helper enabled")
		if err := exprhelpers.InitCrowdsecCTI(cConfig.API.CTI.Key, cConfig.API.CTI.CacheTimeout, cConfig.API.CTI.CacheSize, cConfig.API.CTI.LogLevel); err != nil {
			return errors.Wrap(err, "failed to init crowdsec cti")
		}
	}

	if !cConfig.DisableAPI {
		if cConfig.API.Server.OnlineClient == nil || cConfig.API.Server.OnlineClient.Credentials == nil {
			log.Warningf("Communication with CrowdSec Central API disabled from configuration file")
		}

		if flags.DisableCAPI {
			log.Warningf("Communication with CrowdSec Central API disabled from args")
			cConfig.API.Server.OnlineClient = nil
		}

		apiServer, err := initAPIServer(cConfig)
		if err != nil {
			return errors.Wrap(err, "api server init")
		}

		if !flags.TestMode {
			serveAPIServer(apiServer, apiReady)
		}
	} else {
		apiReady <- true
	}

	if !cConfig.DisableAgent {
		csParsers, err := initCrowdsec(cConfig)
		if err != nil {
			return errors.Wrap(err, "crowdsec init")
		}

		// if it's just linting, we're done
		if !flags.TestMode {
			serveCrowdsec(csParsers, cConfig, agentReady)
		}
	} else {
		agentReady <- true
	}

	if flags.TestMode {
		log.Infof("test done")
		pluginBroker.Kill()
		os.Exit(0)
	}

	if cConfig.Common != nil && cConfig.Common.Daemonize {
		csdaemon.NotifySystemd(log.StandardLogger())
		// wait for signals
		return HandleSignals(cConfig)
	}

	waitChans := make([]<-chan struct{}, 0)

	if !cConfig.DisableAgent {
		waitChans = append(waitChans, crowdsecTomb.Dead())
	}

	if !cConfig.DisableAPI {
		waitChans = append(waitChans, apiTomb.Dead())
	}

	for _, ch := range waitChans {
		<-ch
		switch ch {
		case apiTomb.Dead():
			log.Infof("api shutdown")
		case crowdsecTomb.Dead():
			log.Infof("crowdsec shutdown")
		}
	}
	return nil
}
