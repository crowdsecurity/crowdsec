package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/csdaemon"
	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cticlient/ctiexpr"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func reloadHandler(sig os.Signal) (*csconfig.Config, error) {

	ctx := context.TODO()

	// re-initialize tombs
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}
	pluginTomb = tomb.Tomb{}
	lpMetricsTomb = tomb.Tomb{}

	cConfig, err := LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false)
	if err != nil {
		return nil, err
	}

	if !cConfig.DisableAPI {
		if flags.DisableCAPI {
			log.Warningf("Communication with CrowdSec Central API disabled from args")

			cConfig.API.Server.OnlineClient = nil
		}

		apiServer, err := initAPIServer(ctx, cConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to init api server: %w", err)
		}

		serveAPIServer(apiServer)
	}

	if !cConfig.DisableAgent {
		hub, err := cwhub.NewHub(cConfig.Hub, log.StandardLogger())
		if err != nil {
			return nil, err
		}

		if err = hub.Load(); err != nil {
			return nil, err
		}

		// Reset data files to avoid any potential conflicts with the new configuration
		exprhelpers.ResetDataFiles()

		csParsers, datasources, err := initCrowdsec(cConfig, hub, false)
		if err != nil {
			return nil, fmt.Errorf("unable to init crowdsec: %w", err)
		}

		// reload the simulation state
		if err := cConfig.LoadSimulation(); err != nil {
			log.Errorf("reload error (simulation) : %s", err)
		}

		agentReady := make(chan bool, 1)
		serveCrowdsec(csParsers, cConfig, hub, datasources, agentReady)
	}

	log.Printf("Reload is finished")

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

	done := make(chan error, 1)
	go func() {
		done <- outputsTomb.Wait()
	}()

	// wait for outputs to finish, max 3 seconds
	select {
	case err := <-done:
		if err != nil {
			log.Warningf("Outputs returned error : %s", err)
			reterr = err
		}

		log.Debugf("outputs are done")
	case <-time.After(3 * time.Second):
		// this can happen if outputs are stuck in a http retry loop
		log.Warningf("Outputs didn't finish in time, some events may have not been flushed")
	}

	lpMetricsTomb.Kill(nil)

	if err := lpMetricsTomb.Wait(); err != nil {
		log.Warningf("Metrics returned error : %s", err)
		reterr = err
	}

	log.Debugf("metrics are done")

	// He's dead, Jim.
	crowdsecTomb.Kill(nil)

	// close the potential geoips reader we have to avoid leaking ressources on reload
	exprhelpers.GeoIPClose()

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
			return fmt.Errorf("failed to shut down crowdsec: %w", err)
		}
	}

	if !cConfig.DisableAPI {
		if err := shutdownAPI(); err != nil {
			return fmt.Errorf("failed to shut down api routines: %w", err)
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
			if !ok { // closed
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

	// Always try to stop CPU profiling to avoid passing flags around
	// It's a noop if profiling is not enabled
	defer pprof.StopCPUProfile()

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
					exitChan <- fmt.Errorf("failed shutdown: %w", err)

					break Loop
				}

				if newConfig, err = reloadHandler(s); err != nil {
					exitChan <- fmt.Errorf("reload handler failure: %w", err)

					break Loop
				}

				if newConfig != nil {
					cConfig = newConfig
				}
			// ctrl+C, kill -SIGINT XXXX, kill -SIGTERM XXXX
			case os.Interrupt, syscall.SIGTERM:
				log.Warning("SIGTERM received, shutting down")
				if err = shutdown(s, cConfig); err != nil {
					exitChan <- fmt.Errorf("failed shutdown: %w", err)

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

	if cConfig.API != nil && cConfig.API.Client != nil && cConfig.API.Client.UnregisterOnExit {
		log.Warning("Unregistering watcher")

		lapiClient, err := apiclient.GetLAPIClient()
		if err != nil {
			return err
		}

		_, err = lapiClient.Auth.UnregisterWatcher(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to unregister watcher: %w", err)
		}

		log.Warning("Watcher unregistered")
	}

	return err
}

func Serve(cConfig *csconfig.Config, agentReady chan bool) error {
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}
	pluginTomb = tomb.Tomb{}
	lpMetricsTomb = tomb.Tomb{}

	ctx := context.TODO()

	if cConfig.API.Server != nil && cConfig.API.Server.DbConfig != nil {
		dbClient, err := database.NewClient(ctx, cConfig.API.Server.DbConfig)
		if err != nil {
			return fmt.Errorf("failed to get database client: %w", err)
		}

		err = exprhelpers.Init(dbClient)
		if err != nil {
			return fmt.Errorf("failed to init expr helpers: %w", err)
		}
	} else {
		err := exprhelpers.Init(nil)
		if err != nil {
			return fmt.Errorf("failed to init expr helpers: %w", err)
		}

		log.Warningln("Exprhelpers loaded without database client.")
	}

	if cConfig.API.CTI != nil && cConfig.API.CTI.Enabled != nil && *cConfig.API.CTI.Enabled {
		log.Infof("Crowdsec CTI helper enabled")

		if err := ctiexpr.InitCrowdsecCTI(cConfig.API.CTI.Key, cConfig.API.CTI.CacheTimeout, cConfig.API.CTI.CacheSize, cConfig.API.CTI.LogLevel); err != nil {
			return fmt.Errorf("failed to init crowdsec cti: %w", err)
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

		apiServer, err := initAPIServer(ctx, cConfig)
		if err != nil {
			return fmt.Errorf("api server init: %w", err)
		}

		if !flags.TestMode {
			serveAPIServer(apiServer)
		}
	}

	if !cConfig.DisableAgent {
		hub, err := cwhub.NewHub(cConfig.Hub, log.StandardLogger())
		if err != nil {
			return err
		}

		if err = hub.Load(); err != nil {
			return err
		}

		csParsers, datasources, err := initCrowdsec(cConfig, hub, flags.TestMode)
		if err != nil {
			return fmt.Errorf("crowdsec init: %w", err)
		}

		// if it's just linting, we're done
		if !flags.TestMode {
			serveCrowdsec(csParsers, cConfig, hub, datasources, agentReady)
		} else {
			agentReady <- true
		}
	} else {
		agentReady <- true
	}

	if flags.TestMode {
		log.Infof("Configuration test done")
		pluginBroker.Kill()

		return nil
	}

	isWindowsSvc, err := isWindowsService()
	if err != nil {
		return fmt.Errorf("failed to determine if we are running in windows service mode: %w", err)
	}

	if cConfig.Common != nil && !flags.haveTimeMachine() && !isWindowsSvc {
		_ = csdaemon.Notify(csdaemon.Ready, log.StandardLogger())
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
