package main

import (
	"fmt"
	"os"
	"time"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/sevlyar/go-daemon"
)

//debugHandler is kept as a dev convenience : it shuts down and serialize internal state
func debugHandler(sig os.Signal) error {
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

func reloadHandler(sig os.Signal) error {
	var tmpFile string
	var err error
	//stop go routines
	if err := ShutdownCrowdsecRoutines(); err != nil {
		log.Fatalf("Failed to shut down routines: %s", err)
	}
	if cConfig.Crowdsec != nil && cConfig.Crowdsec.BucketStateDumpDir != "" {
		if tmpFile, err = leaky.DumpBucketsStateAt(time.Now(), cConfig.Crowdsec.BucketStateDumpDir, buckets); err != nil {
			log.Fatalf("Failed dumping bucket state : %s", err)
		}
	}

	if err := leaky.ShutdownAllBuckets(buckets); err != nil {
		log.Fatalf("while shutting down routines : %s", err)
	}

	if !*disableAPI || cConfig.API.Server == nil {
		apiServer, err := initAPIServer()
		if err != nil {
			return fmt.Errorf("unable to init api server: %s", err)
		}
		//restore bucket state
		log.Warningf("Restoring buckets state from %s", tmpFile)
		if err := leaky.LoadBucketsState(tmpFile, buckets, holders); err != nil {
			log.Fatalf("unable to restore buckets : %s", err)
		}
		//reload the simulation state
		if err := cConfig.LoadSimulation(); err != nil {
			log.Errorf("reload error (simulation) : %s", err)
		}

		_, err = runAPIServer(apiServer)
		if err != nil {
			return fmt.Errorf("unable to run api server: %s", err)
		}
	}

	if !*disableCS {
		csParsers, err := initCrowdsec()
		if err != nil {
			return fmt.Errorf("unable to init crowdsec: %s", err)
		}
		err = runCrowdsec(csParsers)
		if err != nil {
			return fmt.Errorf("unable to start crowdsec: %s", err)
		}
	}

	log.Printf("Reload is finished")
	//delete the tmp file, it's safe now :)
	if err := os.Remove(tmpFile); err != nil {
		log.Warningf("Failed to delete temp file (%s) : %s", tmpFile, err)
	}
	return nil
}

func ShutdownCrowdsecRoutines() error {
	var reterr error

	acquisTomb.Kill(nil)
	log.Infof("waiting for acquisition to finish")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("Acquisition returned error : %s", err)
		reterr = err
	}
	log.Infof("acquisition is finished, wait for parser/bucket/ouputs.")
	parsersTomb.Kill(nil)
	if err := parsersTomb.Wait(); err != nil {
		log.Warningf("Parsers returned error : %s", err)
		reterr = err
	}
	log.Infof("parsers is done")
	bucketsTomb.Kill(nil)
	if err := bucketsTomb.Wait(); err != nil {
		log.Warningf("Buckets returned error : %s", err)
		reterr = err
	}
	log.Infof("buckets is done")
	outputsTomb.Kill(nil)
	if err := outputsTomb.Wait(); err != nil {
		log.Warningf("Ouputs returned error : %s", err)
		reterr = err

	}
	log.Infof("outputs are done")

	return reterr
}

func shutdownAPI() error {
	apiTomb.Kill(nil)
	if err := apiTomb.Wait(); err != nil {
		return err
	}
	return nil
}

func shutdownCrowdsec() error {
	crowdsecTomb.Kill(nil)
	if err := crowdsecTomb.Wait(); err != nil {
		return err
	}
	return nil
}

func termHandler(sig os.Signal) error {
	log.Infof("Shutting down routines")
	if err := shutdownCrowdsec(); err != nil {
		log.Errorf("Error encountered while shutting down crowdsec: %s", err)
	}
	if err := shutdownAPI(); err != nil {
		log.Errorf("Error encountered while shutting down api: %s", err)
	}

	log.Warningf("all routines are done, bye.")
	return daemon.ErrStop
}

func serveOneTimeRun() error {
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}
	log.Infof("acquisition is finished, wait for parser/bucket/ouputs.")

	/*
		While it might make sense to want to shut-down parser/buckets/etc. as soon as acquisition is finished,
		we might have some pending buckets : buckets that overflowed, but which LeakRoutine are still alive because they
		are waiting to be able to "commit" (push to db). This can happens specifically in a context where a lot of logs
		are going to trigger overflow (ie. trigger buckets with ~100% of the logs triggering an overflow).

		To avoid this (which would mean that we would "lose" some overflows), let's monitor the number of live buckets.
		However, because of the blackhole mechanism, you can't really wait for the number of LeakRoutine to go to zero (we might have to wait $blackhole_duration).

		So : we are waiting for the number of buckets to stop decreasing before returning. "how long" we should wait is a bit of the trick question,
		as some operations (ie. reverse dns or such in post-overflow) can take some time :)
	*/

	bucketCount := leaky.LeakyRoutineCount
	rounds := 0
	successiveStillRounds := 0
	for {
		rounds++
		time.Sleep(5 * time.Second)
		currBucketCount := leaky.LeakyRoutineCount
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
	}

	time.Sleep(5 * time.Second)

	// wait for the parser to parse all events
	if err := ShutdownCrowdsecRoutines(); err != nil {
		log.Errorf("failed shutting down routines : %s", err)
	}
	dumpMetrics()
	log.Warningf("all routines are done, bye.")
	return nil
}

func Serve(daemonCTX daemon.Context) error {
	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}
	apiTomb = tomb.Tomb{}
	crowdsecTomb = tomb.Tomb{}

	if cConfig.Common != nil && !cConfig.Common.Daemonize {
		defer daemonCTX.Release() //nolint:errcheck // won't bother checking this error in defer statement
		err := daemon.ServeSignals()
		if err != nil {
			log.Errorf("serveDaemon error : %s", err.Error())
		}
	}

	if !*disableAPI || cConfig.API.Server == nil {
		apiServer, err := initAPIServer()
		if err != nil {
			return fmt.Errorf("unable to init api server: %s", err)
		}
		if !cConfig.Crowdsec.LintOnly {
			httpAPIServer, err := runAPIServer(apiServer)
			if err != nil {
				return fmt.Errorf("unable to run api server: %s", err)
			}
			serveAPIServer(httpAPIServer)
		}
	}

	log.Printf("local api launched")

	if !*disableCS {
		csParsers, err := initCrowdsec()
		if err != nil {
			return fmt.Errorf("unable to init crowdsec: %s", err)
		}
		/* if it's just linting, we're done */
		if cConfig.Crowdsec.LintOnly {
			log.Infof("lint done")
			os.Exit(0)
		}
		if cConfig.Common != nil && !cConfig.Common.Daemonize {
			if err := serveOneTimeRun(); err != nil {
				log.Errorf(err.Error())
			}
		} else {
			serveCrowdsec(csParsers)
		}
	}

	for {
		select {
		case <-apiTomb.Dead():
			if err := shutdownCrowdsec(); err != nil {
				log.Fatalf("unable to shutdown crowdsec: %s", err)
			}
			os.Exit(0)
		case <-crowdsecTomb.Dead():
			if err := shutdownAPI(); err != nil {
				log.Fatalf("unable to shutdown api: %s", err)
			}
			os.Exit(0)
		}
	}
}
