//go:build !windows

package main

import (
	"context"
	"fmt"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/go-cs-lib/trace"
	"github.com/crowdsecurity/go-cs-lib/version"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
)

func StartRunSvc() error {
	var (
		cConfig *csconfig.Config
		err     error
	)

	defer trace.CatchPanic("crowdsec/StartRunSvc")

	// Always try to stop CPU profiling to avoid passing flags around
	// It's a noop if profiling is not enabled
	defer pprof.StopCPUProfile()

	if cConfig, err = LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false); err != nil {
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
	} else {
		// avoid leaking the channel
		go func() {
			<-agentReady
		}()
	}

	return Serve(cConfig, agentReady)
}
