package main

import (
	"fmt"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func StartRunSvc() error {
	const svcName = "CrowdSec"
	const svcDescription = "Crowdsec IPS/IDS"

	isRunninginService, err := svc.IsWindowsService()
	if err != nil {
		return errors.Wrap(err, "failed to determine if we are running in windows service mode")
	}
	if isRunninginService {
		return runService(svcName)
	}

	if flags.WinSvc == "Install" {
		err = installService(svcName, svcDescription)
		if err != nil {
			return errors.Wrapf(err, "failed to %s %s", flags.WinSvc, svcName)
		}
	} else if flags.WinSvc == "Remove" {
		err = removeService(svcName)
		if err != nil {
			return errors.Wrapf(err, "failed to %s %s", flags.WinSvc, svcName)
		}
	} else if flags.WinSvc == "Start" {
		err = startService(svcName)
		if err != nil {
			return errors.Wrapf(err, "failed to %s %s", flags.WinSvc, svcName)
		}
	} else if flags.WinSvc == "Stop" {
		err = controlService(svcName, svc.Stop, svc.Stopped)
		if err != nil {
			return errors.Wrapf(err, "failed to %s %s", flags.WinSvc, svcName)
		}
	} else if flags.WinSvc == "" {
		return WindowsRun()
	} else {
		return fmt.Errorf("Invalid value for winsvc parameter: %s", flags.WinSvc)
	}
	return nil
}

func WindowsRun() error {
	var (
		cConfig *csconfig.Config
		err     error
	)

	cConfig, err = csconfig.NewConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI)
	if err != nil {
		return err
	}
	if err := LoadConfig(cConfig); err != nil {
		return err
	}
	// Configure logging
	log.Infof("Crowdsec %s", cwversion.VersionStr())

	if bincoverTesting != "" {
		log.Debug("coverage report is enabled")
	}

	apiReady := make(chan bool, 1)
	agentReady := make(chan bool, 1)

	// Enable profiling early
	if cConfig.Prometheus != nil {
		var dbClient *database.Client
		var err error

		if cConfig.DbConfig != nil {
			dbClient, err = database.NewClient(cConfig.DbConfig)

			if err != nil {
				log.Fatalf("unable to create database client: %s", err)
			}
		}
		registerPrometheus(cConfig.Prometheus)
		go servePrometheus(cConfig.Prometheus, dbClient, apiReady, agentReady)
	}
	return Serve(cConfig, apiReady, agentReady)
}
