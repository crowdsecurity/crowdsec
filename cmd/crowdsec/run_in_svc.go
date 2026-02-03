//go:build !windows

package main

import (
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
)

func isWindowsService() (bool, error) {
	return false, nil
}

func StartRunSvc(
	ctx context.Context,
	cConfig *csconfig.Config,
	sd *StateDumper,
) error {
	defer trace.CatchPanic("crowdsec/StartRunSvc")

	// Always try to stop CPU profiling to avoid passing flags around
	// It's a noop if profiling is not enabled
	defer pprof.StopCPUProfile()

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
	} else {
		// avoid leaking the channel
		go func() {
			<-agentReady
		}()
	}

	return Serve(ctx, cConfig, agentReady, sd)
}
