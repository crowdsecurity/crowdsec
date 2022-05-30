package main

import (
	"os"

	"github.com/confluentinc/bincover"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/sys/windows/svc"
)

func StartRunSvc() {

	const svcName = "CrowdSec"
	const svcDescription = "Crowdsec IPS/IDS"

	isRunninginService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if we are running in windows service mode: %v", err)
	}
	if isRunninginService {
		runService(svcName)
		return
	}

	if flags.WinSvc == "Install" {
		err = installService(svcName, svcDescription)
		if err != nil {
			log.Fatalf("failed to %s %s: %v", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Remove" {
		err = removeService(svcName)
		if err != nil {
			log.Fatalf("failed to %s %s: %v", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Start" {
		err = startService(svcName)
		if err != nil {
			log.Fatalf("failed to %s %s: %v", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "Stop" {
		err = controlService(svcName, svc.Stop, svc.Stopped)
		if err != nil {
			log.Fatalf("failed to %s %s: %v", flags.WinSvc, svcName, err)
		}
	} else if flags.WinSvc == "" {
		WindowsRun()
	} else {
		log.Fatalf("Invalid value for winsvc parameter: %s", flags.WinSvc)
	}

}

func WindowsRun() {

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

	if bincoverTesting != "" {
		log.Debug("coverage report is enabled")
	}

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
			if bincoverTesting != "" {
				os.Exit(exitCode)
			}
			bincover.ExitCode = exitCode
		}
	}
}
