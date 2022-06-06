//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package main

import (
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

func StartRunSvc() error {
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
		return err
	}
	if err := LoadConfig(cConfig); err != nil {
		return err
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel,
		cConfig.Common.LogMaxSize, cConfig.Common.LogMaxFiles, cConfig.Common.LogMaxAge, cConfig.Common.CompressLogs); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	if bincoverTesting != "" {
		log.Debug("coverage report is enabled")
	}

	// Enable profiling early
	if cConfig.Prometheus != nil {
		go registerPrometheus(cConfig.Prometheus)
	}
	return Serve(cConfig)
}
