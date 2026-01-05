package main

import (
	"context"
	"errors"
	"fmt"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/go-cs-lib/trace"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/logging"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

var (
	// tombs for the parser, buckets and outputs.
	acquisTomb    tomb.Tomb
	outputsTomb   tomb.Tomb
	apiTomb       tomb.Tomb
	crowdsecTomb  tomb.Tomb
	pluginTomb    tomb.Tomb

	flags Flags

	// the state of acquisition
	dataSources []acquisition.DataSource
	// the state of the buckets
	holders []leakybucket.BucketFactory
	buckets *leakybucket.Buckets

	logLines   chan pipeline.Event
	inEvents  chan pipeline.Event
	outEvents chan pipeline.Event // the buckets init returns its own chan that is used for multiplexing
	pluginBroker      csplugin.PluginBroker
)

func LoadBuckets(cConfig *csconfig.Config, hub *cwhub.Hub) error {
	var err error

	buckets = leakybucket.NewBuckets()

	scenarios := hub.GetInstalledByType(cwhub.SCENARIOS, false)

	log.Infof("Loading %d scenario files", len(scenarios))

	holders, outEvents, err = leakybucket.LoadBuckets(cConfig.Crowdsec, hub, scenarios, buckets, flags.OrderEvent)
	if err != nil {
		return err
	}

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		for holderIndex := range holders {
			holders[holderIndex].Profiling = true
		}
	}

	return nil
}

func LoadAcquisition(ctx context.Context, cConfig *csconfig.Config, hub *cwhub.Hub) ([]acquisition.DataSource, error) {
	if flags.SingleFileType != "" && flags.OneShotDSN != "" {
		flags.Labels["type"] = flags.SingleFileType

		ds, err := acquisition.LoadAcquisitionFromDSN(ctx, flags.OneShotDSN, flags.Labels, flags.Transform, hub)
		if err != nil {
			return nil, err
		}
		dataSources = append(dataSources, ds)
	} else {
		dss, err := acquisition.LoadAcquisitionFromFiles(ctx, cConfig.Crowdsec, cConfig.Prometheus, hub)
		if err != nil {
			return nil, err
		}
		dataSources = dss
	}

	if len(dataSources) == 0 {
		return nil, errors.New("no datasource enabled")
	}

	return dataSources, nil
}

// LoadConfig returns a configuration parsed from configuration file
func LoadConfig(configFile string, disableAgent bool, disableAPI bool, quiet bool) (*csconfig.Config, error) {
	cConfig, _, err := csconfig.NewConfig(configFile, disableAgent, disableAPI, quiet)
	if err != nil {
		return nil, fmt.Errorf("while loading configuration file: %w", err)
	}

	if err := trace.Init(filepath.Join(cConfig.ConfigPaths.DataDir, "trace")); err != nil {
		return nil, fmt.Errorf("while setting up trace directory: %w", err)
	}

	if flags.LogLevel != 0 {
		cConfig.Common.LogLevel = flags.LogLevel
		if cConfig.API != nil && cConfig.API.Server != nil {
			cConfig.API.Server.LogLevel = flags.LogLevel
		}
	}

	if flags.DumpDir != "" {
		parser.ParseDump = true
		leakybucket.BucketPourTrack = true
	}

	if flags.haveTimeMachine() {
		// in time-machine mode, we want to see what's happening
		cConfig.Common.LogMedia = "stdout"
	}

	if err := logging.SetupStandardLogger(cConfig.Common.LogConfig, cConfig.Common.LogLevel, cConfig.Common.ForceColorLogs); err != nil {
		return nil, err
	}

	if cConfig.Common.LogMedia != "stdout" {
		log.AddHook(newFatalHook())
	}

	if err := csconfig.LoadFeatureFlagsFile(configFile, log.StandardLogger()); err != nil {
		return nil, err
	}

	if !cConfig.DisableAgent {
		if err := cConfig.LoadCrowdsec(); err != nil {
			return nil, err
		}
	}

	if !cConfig.DisableAPI {
		if err := cConfig.LoadAPIServer(false, false); err != nil {
			return nil, err
		}
	}

	if !cConfig.DisableAgent && (cConfig.API == nil || cConfig.API.Client == nil || cConfig.API.Client.Credentials == nil) {
		return nil, errors.New("missing local API credentials for crowdsec agent, abort")
	}

	if cConfig.DisableAPI && cConfig.DisableAgent {
		return nil, errors.New("you must run at least the API Server or crowdsec")
	}

	if flags.OneShotDSN != "" && flags.SingleFileType == "" {
		return nil, errors.New("-dsn requires a -type argument")
	}

	if flags.Transform != "" && flags.OneShotDSN == "" {
		return nil, errors.New("-transform requires a -dsn argument")
	}

	if flags.SingleFileType != "" && flags.OneShotDSN == "" {
		return nil, errors.New("-type requires a -dsn argument")
	}

	if flags.SingleFileType != "" && flags.OneShotDSN != "" {
		if cConfig.API != nil && cConfig.API.Server != nil {
			cConfig.API.Server.OnlineClient = nil
		}
	}

	if cConfig.Common.PidDir != "" {
		log.Warn("Deprecation warning: the pid_dir config can be safely removed and is not required")
	}

	// recap of the enabled feature flags, because logging
	// was not enabled when we set them from envvars
	if fflist := csconfig.ListFeatureFlags(); fflist != "" {
		log.Infof("Enabled feature flags: %s", fflist)
	}

	return cConfig, nil
}

// crowdsecT0 can be used to measure start time of services,
// or uptime of the application
var crowdsecT0 time.Time

func run(flags Flags) error {
	if flags.CPUProfile != "" {
		f, err := os.Create(flags.CPUProfile)
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}

		log.Infof("CPU profile will be written to %s", flags.CPUProfile)

		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("could not start CPU profile: %s", err)
		}

		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	ctx := context.Background()

	cConfig, err := LoadConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI, false)
	if err != nil {
		return err
	}

	return StartRunSvc(ctx, cConfig)
}

func main() {
	// Add a timestamp to avoid the ugly [0000]
	// The initial log level is INFO, even if the user provided an -error or -warning flag
	// because we need feature flags before parsing cli flags.
	log.SetFormatter(&log.TextFormatter{TimestampFormat: time.RFC3339, FullTimestamp: true})

	if err := fflag.RegisterAllFeatures(); err != nil {
		log.Fatalf("failed to register features: %s", err)
	}

	// some features can require configuration or command-line options,
	// so we need to parse them asap. we'll load from feature.yaml later.
	if err := csconfig.LoadFeatureFlagsEnv(log.StandardLogger()); err != nil {
		log.Fatalf("failed to set feature flags from environment: %s", err)
	}

	crowdsecT0 = time.Now()

	parsedFlags, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, color.RedString("Error:"), err)
		// the flag package exits with 2 in case of unknown flag,
		// we do the same for extra arguments
		os.Exit(2)
	}

	flags = parsedFlags

	if flags.PrintVersion {
		os.Stdout.WriteString(cwversion.FullString())
		return
	}

	if err := run(flags); err != nil {
		log.Fatal(err)
	}
}
