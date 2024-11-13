package main

import (
	"context"
	"fmt"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"

	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func StartRunSvc() error {
	const svcName = "CrowdSec"
	const svcDescription = "Crowdsec IPS/IDS"

	defer trace.CatchPanic("crowdsec/StartRunSvc")

	// Always try to stop CPU profiling to avoid passing flags around
	// It's a noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	isRunninginService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("failed to determine if we are running in windows service mode: %w", err)
	}
	if isRunninginService {
		return runService(svcName)
	}

	if flags.WinSvc == "Install" {
		err = installService(svcName, svcDescription)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Remove" {
		err = removeService(svcName)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Start" {
		err = startService(svcName)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Stop" {
		err = controlService(svcName, svc.Stop, svc.Stopped)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
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

	cConfig, err = LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false)
	if err != nil {
		return err
	}

	log.Infof("Crowdsec %s", version.String())

	agentReady := make(chan bool, 1)

	// Enable profiling early
	if cConfig.Prometheus != nil {
		var dbClient *database.Client
		var err error

		ctx := context.TODO()

		if cConfig.DbConfig != nil {
			dbClient, err = database.NewClient(ctx, cConfig.DbConfig)

			if err != nil {
				return fmt.Errorf("unable to create database client: %w", err)
			}
		}
		registerPrometheus(cConfig.Prometheus)
		go servePrometheus(cConfig.Prometheus, dbClient, agentReady)
	}
	return Serve(cConfig, agentReady)
}
