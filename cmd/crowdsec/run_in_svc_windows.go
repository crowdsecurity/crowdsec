package main

import (
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"

	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
)

func isWindowsService() (bool, error) {
	return svc.IsWindowsService()
}

func StartRunSvc(ctx context.Context, cConfig *csconfig.Config, pourCollector *leakybucket.PourCollector) error {
	const svcName = "CrowdSec"
	const svcDescription = "Crowdsec IPS/IDS"

	defer trace.CatchPanic("crowdsec/StartRunSvc")

	// Always try to stop CPU profiling to avoid passing flags around
	// It's a noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	isRunninginService, err := isWindowsService()
	if err != nil {
		return fmt.Errorf("failed to determine if we are running in windows service mode: %w", err)
	}
	if isRunninginService {
		return runService(svcName, pourCollector)
	}

	switch flags.WinSvc {
	case "Install":
		err = installService(svcName, svcDescription)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	case "Remove":
		err = removeService(svcName)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	case "Start":
		err = startService(svcName)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	case "Stop":
		err = controlService(svcName, svc.Stop, svc.Stopped)
		if err != nil {
			return fmt.Errorf("failed to %s %s: %w", flags.WinSvc, svcName, err)
		}
	case "":
		return WindowsRun(ctx, cConfig, pourCollector)
	default:
		return fmt.Errorf("Invalid value for winsvc parameter: %s", flags.WinSvc)
	}

	return nil
}

func WindowsRun(ctx context.Context, cConfig *csconfig.Config, pourCollector *leakybucket.PourCollector) error {
	if fflag.PProfBlockProfile.IsEnabled() {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		log.Warn("pprof block/mutex profiling enabled, expect a performance hit")
	}

	log.Infof("Crowdsec %s", version.String())

	agentReady := make(chan bool, 1)

	// Enable profiling early
	if cConfig.Prometheus != nil {
		var dbClient *database.Client
		var err error

		if cConfig.DbConfig != nil {
			dbCfg := cConfig.DbConfig
			dbClient, err = database.NewClient(ctx, dbCfg, dbCfg.NewLogger())

			if err != nil {
				return fmt.Errorf("unable to create database client: %w", err)
			}
		}
		registerPrometheus(cConfig.Prometheus)
		go servePrometheus(cConfig.Prometheus, dbClient, agentReady)
	}
	return Serve(ctx, cConfig, agentReady, pourCollector)
}
