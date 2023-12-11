//go:build !windows

package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"

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

	// Set a default logger with level=fatal on stderr,
	// in addition to the one we configure afterwards
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	if cConfig, err = LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false); err != nil {
		return err
	}

	log.Infof("Crowdsec %s", version.String())

	apiReady := make(chan bool, 1)
	agentReady := make(chan bool, 1)

	// Enable profiling early
	if cConfig.Prometheus != nil {
		var dbClient *database.Client
		var err error

		if cConfig.DbConfig != nil {
			dbClient, err = database.NewClient(cConfig.DbConfig)

			if err != nil {
				return fmt.Errorf("unable to create database client: %s", err)
			}
		}
		registerPrometheus(cConfig.Prometheus)
		go servePrometheus(cConfig.Prometheus, dbClient, apiReady, agentReady)
	}
	return Serve(cConfig, apiReady, agentReady)
}
