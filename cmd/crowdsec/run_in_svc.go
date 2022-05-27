//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package main

import (
	"os"

	"github.com/confluentinc/bincover"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

func StartRunSvc() {

	var (
		cConfig *csconfig.Config
		err     error
	)

	log.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
		},
	})

	cConfig, err = csconfig.NewConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI)
	if err != nil {
		log.Fatalf(err.Error())
	}
	if err := LoadConfig(cConfig); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel,
		cConfig.Common.LogMaxSize, cConfig.Common.LogMaxFiles, cConfig.Common.LogMaxAge, cConfig.Common.CompressLogs); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	// Enable profiling early
	if cConfig.Prometheus != nil {
		go registerPrometheus(cConfig.Prometheus)
	}

	if exitCode, err := Serve(cConfig); err != nil {
		if err != nil {
			// this method of logging a fatal error does not
			// trigger a program exit (as stated by the authors, it
			// is not going to change in logrus to keep backward
			// compatibility), and allows us to report coverage.
			log.NewEntry(log.StandardLogger()).Log(log.FatalLevel, err)
			if !bincoverTesting {
				os.Exit(exitCode)
			}
			bincover.ExitCode = exitCode
		}
	}
}
