//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package main

import (
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

func StartRunSvc() error {
	var (
		cConfig *csconfig.Config
		err     error
	)

	// Set a default logger with level=fatal on stderr,
	// in addition to the one we configure afterwards
	log.AddHook(&writer.Hook{
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	cConfig, err = csconfig.NewConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI)
	if err != nil {
		return err
	}
	if err := LoadConfig(cConfig); err != nil {
		return err
	}

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
