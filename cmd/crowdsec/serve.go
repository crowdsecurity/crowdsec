package main

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	log "github.com/sirupsen/logrus"

	"github.com/sevlyar/go-daemon"
)

func reloadHandler(sig os.Signal) error {
	dumpMetrics()
	return nil
}

func termHandler(sig os.Signal) error {
	log.Warningf("Shutting down routines")

	acquisTomb.Kill(nil)
	log.Infof("waiting for acquisition to finish")
	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("Acquisition returned error : %s", err)
	}
	log.Infof("acquisition is finished, wait for parser/bucket/ouputs.")
	parsersTomb.Kill(nil)
	if err := parsersTomb.Wait(); err != nil {
		log.Warningf("Parsers returned error : %s", err)
	}
	log.Infof("parsers is done")
	bucketsTomb.Kill(nil)
	if err := bucketsTomb.Wait(); err != nil {
		log.Warningf("Buckets returned error : %s", err)
	}
	log.Infof("buckets is done")
	outputsTomb.Kill(nil)
	if err := outputsTomb.Wait(); err != nil {
		log.Warningf("Ouputs returned error : %s", err)

	}
	log.Infof("ouputs is done")
	dumpMetrics()
	log.Warningf("all routines are done, bye.")
	return daemon.ErrStop
}

func serveDaemon() error {
	var daemonCTX *daemon.Context

	daemon.SetSigHandler(termHandler, syscall.SIGTERM)
	daemon.SetSigHandler(reloadHandler, syscall.SIGHUP)

	daemonCTX = &daemon.Context{
		PidFileName: cConfig.PIDFolder + "/crowdsec.pid",
		PidFilePerm: 0644,
		WorkDir:     "./",
		Umask:       027,
	}

	d, err := daemonCTX.Reborn()
	if err != nil {
		return fmt.Errorf("unable to run daemon: %s ", err.Error())
	}
	if d != nil {
		return nil
	}
	defer daemonCTX.Release() //nolint:errcheck // won't bother checking this error in defer statement
	err = daemon.ServeSignals()
	if err != nil {
		return fmt.Errorf("serveDaemon error : %s", err.Error())
	}
	return nil
}

func serveOneTimeRun(outputRunner outputs.Output) error {
	log.Infof("waiting for acquisition to finish")

	if err := acquisTomb.Wait(); err != nil {
		log.Warningf("acquisition returned error : %s", err)
	}
	log.Infof("acquisition is finished, wait for parser/bucket/ouputs.")

	//let's wait more than enough for in-flight events to be parsed.
	time.Sleep(5 * time.Second)

	// wait for the parser to parse all events
	parsersTomb.Kill(nil)
	if err := parsersTomb.Wait(); err != nil {
		log.Warningf("parsers returned error : %s", err)
	}
	log.Infof("parsers is done")

	// wait for the bucket to pour all events
	bucketsTomb.Kill(nil)
	if err := bucketsTomb.Wait(); err != nil {
		log.Warningf("buckets returned error : %s", err)
	}
	log.Infof("buckets is done")

	// wait for output to output all event
	outputsTomb.Kill(nil)
	if err := outputsTomb.Wait(); err != nil {
		log.Warningf("ouputs returned error : %s", err)

	}
	log.Infof("ouputs is done")
	dumpMetrics()
	outputRunner.Flush()
	log.Warningf("all routines are done, bye.")
	return nil
}

func serve(outputRunner outputs.Output) error {
	var err error
	if cConfig.Daemonize {
		if err = serveDaemon(); err != nil {
			return fmt.Errorf(err.Error())
		}
	} else {
		if err = serveOneTimeRun(outputRunner); err != nil {
			return fmt.Errorf(err.Error())
		}
	}
	return nil
}
