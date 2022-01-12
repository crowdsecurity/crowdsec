package main

import (
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/sys/windows/svc"
)

func StartRunSvc() {

	const svcName = "CrowdSec"
	const svcDisplayName = "massively multiplayer firewall"

	isRunninginService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if we are running in windows service mode: %v", err)
	}
	if isRunninginService {
		runService(svcName, false)
		return
	}

	if flags.WinSvc == "Install" {
		err = installService(svcName, svcDisplayName)
		return
	} else if flags.WinSvc == "Remove" {
		err = removeService(svcName)
		return
	} else if flags.WinSvc == "Start" {
		err = startService(svcName)
		return
	} else if flags.WinSvc == "Stop" {
		err = controlService(svcName, svc.Stop, svc.Stopped)
	}
	if err != nil {
		log.Fatalf("failed to %s %s: %v", flags.WinSvc, svcName, err)
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
		elog.Error(1, err.Error())

	}
	if err := LoadConfig(cConfig); err != nil {
		elog.Error(1, err.Error())

	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel); err != nil {

		elog.Error(1, err.Error())
	}

	elog.Info(1, "Crowdsec"+cwversion.VersionStr())
	// Enable profiling early
	if cConfig.Prometheus != nil {
		go registerPrometheus(cConfig.Prometheus)
	}

	if err := Serve(cConfig); err != nil {

		elog.Error(1, err.Error())
	}
}
