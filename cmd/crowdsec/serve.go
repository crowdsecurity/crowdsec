package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/pkg/errors"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	//"github.com/sevlyar/go-daemon"
)

//debugHandler is kept as a dev convenience : it shuts down and serialize internal state
func debugHandler(sig os.Signal, cConfig *csconfig.GlobalConfig) error {
	var tmpFile string
	var err error
	//stop go routines
	if err := ShutdownCrowdsecRoutines(); err != nil {
		log.Warningf("Failed to shut down routines: %s", err)
	}
	//todo : properly stop acquis with the tail readers
	if tmpFile, err = leaky.DumpBucketsStateAt(time.Now(), cConfig.Crowdsec.BucketStateDumpDir, buckets); err != nil {
		log.Warningf("Failed dumping bucket state : %s", err)
	}
	if err := leaky.ShutdownAllBuckets(buckets); err != nil {
		log.Warningf("while shutting down routines : %s", err)
	}
	log.Printf("shutdown is finished buckets are in %s", tmpFile)
	return nil
}

func reloadHandler(sig os.Signal, cConfig *csconfig.GlobalConfig) error {
	var tmpFile string
	var err error

	//stop go routines
	if !disableAgent {
		if err := shutdownCrowdsec(); err != nil {
			log.Fatalf("Failed to shut down crowdsec routines: %s", err)
		}
		if cConfig.Crowdsec != nil && cConfig.Crowdsec.BucketStateDumpDir != "" {
			if tmpFile, err = leaky.DumpBucketsStateAt(time.Now(), cConfig.Crowdsec.BucketStateDumpDir, buckets); err != nil {
				log.Fatalf("Failed dumping bucket state : %s", err)
			}
		}

		if err := leaky.ShutdownAllBuckets(buckets); err != nil {
			log.Fatalf("while shutting down routines : %s", err)
		}
	}

	if !disableAPI {
		if err := shutdownAPI(); err != nil {
			log.Fatalf("Failed to shut down api routines: %s", err)
		}
	}

	/*
	 re-init tombs
	*/
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}

	if err := LoadConfig(cConfig); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	if !disableAPI {
		apiServer, err := initAPIServer(cConfig)
		if err != nil {
			return fmt.Errorf("unable to init api server: %s", err)
		}

		serveAPIServer(apiServer)
	}

	if !disableAgent {
		csParsers, err := initCrowdsec(cConfig)
		if err != nil {
			return fmt.Errorf("unable to init crowdsec: %s", err)
		}
		//restore bucket state
		if tmpFile != "" {
			log.Warningf("we are now using %s as a state file", tmpFile)
			cConfig.Crowdsec.BucketStateFile = tmpFile
		}
		//reload the simulation state
		if err := cConfig.LoadSimulation(); err != nil {
			log.Errorf("reload error (simulation) : %s", err)
		}
		serveCrowdsec(csParsers, cConfig)
	}

	log.Printf("Reload is finished")
	//delete the tmp file, it's safe now :)
	if tmpFile != "" {
		if err := os.Remove(tmpFile); err != nil {
			log.Warningf("Failed to delete temp file (%s) : %s", tmpFile, err)
		}
	}
	return nil
}

func ShutdownCrowdsecRoutines() error {
	var reterr error

	log.Debugf("Shutting down crowdsec sub-routines")
	acquisTomb.Kill(nil)
	log.Debugf("waiting for acquisition to finish")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("Acquisition returned error : %s", err)
		reterr = err
	}
	log.Debugf("acquisition is finished, wait for parser/bucket/ouputs.")
	parsersTomb.Kill(nil)
	if err := parsersTomb.Wait(); err != nil {
		log.Warningf("Parsers returned error : %s", err)
		reterr = err
	}
	time.Sleep(1 * time.Second) //ugly workaround for now to ensure PourItemtoholders are finished
	log.Debugf("parsers is done")
	bucketsTomb.Kill(nil)
	if err := bucketsTomb.Wait(); err != nil {
		log.Warningf("Buckets returned error : %s", err)
		reterr = err
	}
	log.Debugf("buckets is done")
	outputsTomb.Kill(nil)
	if err := outputsTomb.Wait(); err != nil {
		log.Warningf("Ouputs returned error : %s", err)
		reterr = err

	}
	log.Debugf("outputs are done")
	//everything is dead johny
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

func termHandler(sig os.Signal) error {
	if err := shutdownCrowdsec(); err != nil {
		log.Errorf("Error encountered while shutting down crowdsec: %s", err)
	}
	if err := shutdownAPI(); err != nil {
		log.Errorf("Error encountered while shutting down api: %s", err)
	}
	log.Debugf("termHandler done")
	return nil
}

func HandleSignals(cConfig *csconfig.GlobalConfig) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGHUP,
		syscall.SIGTERM)

	exitChan := make(chan int)
	go func() {
		defer types.CatchPanic("crowdsec/HandleSignals")
		for {
			s := <-signalChan
			switch s {
			// kill -SIGHUP XXXX
			case syscall.SIGHUP:
				log.Warningf("SIGHUP received, reloading")
				if err := reloadHandler(s, cConfig); err != nil {
					log.Fatalf("Reload handler failure : %s", err)
				}
			// kill -SIGTERM XXXX
			case syscall.SIGTERM:
				log.Warningf("SIGTERM received, shutting down")
				if err := termHandler(s); err != nil {
					log.Fatalf("Term handler failure : %s", err)
				}
				exitChan <- 0
			}
		}
	}()

	code := <-exitChan
	log.Warningf("Crowdsec service shutting down")
	os.Exit(code)
}

func Serve(cConfig *csconfig.GlobalConfig) error {
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}

	if !disableAPI {
		apiServer, err := initAPIServer(cConfig)
		if err != nil {
			return errors.Wrap(err, "api server init")
		}
		if !flags.TestMode {
			serveAPIServer(apiServer)
		}
	}

	if !disableAgent {
		csParsers, err := initCrowdsec(cConfig)
		if err != nil {
			return errors.Wrap(err, "crowdsec init")
		}
		/* if it's just linting, we're done */
		if !flags.TestMode {
			serveCrowdsec(csParsers, cConfig)
		}
	}
	if flags.TestMode {
		log.Infof("test done")
		os.Exit(0)
	}

	if cConfig.Common != nil && cConfig.Common.Daemonize {
		sent, err := daemon.SdNotify(false, daemon.SdNotifyReady)
		if !sent || err != nil {
			log.Errorf("Failed to notify(sent: %v): %v", sent, err)
		}
		/*wait for signals*/
		HandleSignals(cConfig)
	} else {
		for {
			select {
			case <-apiTomb.Dead():
				log.Infof("api shutdown")
				os.Exit(0)
			case <-crowdsecTomb.Dead():
				log.Infof("crowdsec shutdown")
				os.Exit(0)
			}
		}
	}
	return nil
}
