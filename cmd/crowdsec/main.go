package main

import (
	"flag"
	"fmt"
	"os"

	_ "net/http/pprof"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"sort"

	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
)

var (
	/*tombs for the parser, buckets and outputs.*/
	acquisTomb   tomb.Tomb
	parsersTomb  tomb.Tomb
	bucketsTomb  tomb.Tomb
	outputsTomb  tomb.Tomb
	apiTomb      tomb.Tomb
	crowdsecTomb tomb.Tomb

	disableAPI   bool
	disableAgent bool

	flags *Flags

	/*global crowdsec config*/
	cConfig *csconfig.GlobalConfig
	/*the state of acquisition*/
	acquisitionCTX *acquisition.FileAcquisCtx
	/*the state of the buckets*/
	holders         []leaky.BucketFactory
	buckets         *leaky.Buckets
	outputEventChan chan types.Event //the buckets init returns its own chan that is used for multiplexing
	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
)

type Flags struct {
	ConfigFile     string
	TraceLevel     bool
	DebugLevel     bool
	InfoLevel      bool
	PrintVersion   bool
	SingleFilePath string
	SingleFileType string
	SingleFileJsonOutput string
	TestMode       bool
	DisableAgent   bool
	DisableAPI     bool
}

type parsers struct {
	ctx             *parser.UnixParserCtx
	povfwctx        *parser.UnixParserCtx
	stageFiles      []parser.Stagefile
	povfwStageFiles []parser.Stagefile
	nodes           []parser.Node
	povfwnodes      []parser.Node
	enricherCtx     []parser.EnricherCtx
}

// Return new parsers
// nodes and povfwnodes are already initialized in parser.LoadStages
func newParsers() *parser.Parsers {
	parsers := &parser.Parsers{
		Ctx:             &parser.UnixParserCtx{},
		Povfwctx:        &parser.UnixParserCtx{},
		StageFiles:      make([]parser.Stagefile, 0),
		PovfwStageFiles: make([]parser.Stagefile, 0),
	}
	for _, itemType := range []string{cwhub.PARSERS, cwhub.PARSERS_OVFLW} {
		for _, hubParserItem := range cwhub.GetItemMap(itemType) {
			if hubParserItem.Installed {
				stagefile := parser.Stagefile{
					Filename: hubParserItem.LocalPath,
					Stage:    hubParserItem.Stage,
				}
				if itemType == cwhub.PARSERS {
					parsers.StageFiles = append(parsers.StageFiles, stagefile)
				}
				if itemType == cwhub.PARSERS_OVFLW {
					parsers.PovfwStageFiles = append(parsers.PovfwStageFiles, stagefile)
				}
			}
		}
	}
	if parsers.StageFiles != nil {
		sort.Slice(parsers.StageFiles,func(i, j int) bool {
			return parsers.StageFiles[i].Filename < parsers.StageFiles[j].Filename
		})
	}
	if parsers.PovfwStageFiles != nil {
		sort.Slice(parsers.StageFiles,func(i,j int)bool  {
			return parsers.PovfwStageFiles[i].Filename < parsers.PovfwStageFiles[j].Filename
		}
	})

	return parsers
}

func LoadBuckets(cConfig *csconfig.GlobalConfig) error {

	var (
		err   error
		files []string
	)
	for _, hubScenarioItem := range cwhub.GetItemMap(cwhub.SCENARIOS) {
		if hubScenarioItem.Installed {
			files = append(files, hubScenarioItem.LocalPath)
		}
	}

	log.Infof("Loading %d scenario files", len(files))
	holders, outputEventChan, err = leaky.LoadBuckets(cConfig.Crowdsec, files)

	if err != nil {
		return fmt.Errorf("Scenario loading failed : %v", err)
	}
	buckets = leaky.NewBuckets()

	/*restore as well previous state if present*/
	if cConfig.Crowdsec.BucketStateFile != "" {
		log.Warningf("Restoring buckets state from %s", cConfig.Crowdsec.BucketStateFile)
		if err := leaky.LoadBucketsState(cConfig.Crowdsec.BucketStateFile, buckets, holders); err != nil {
			return fmt.Errorf("unable to restore buckets : %s", err)
		}
	}
	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		for holderIndex := range holders {
			holders[holderIndex].Profiling = true
		}
	}
	return nil
}

func LoadAcquisition(cConfig *csconfig.GlobalConfig) error {
	var err error
	var tmpctx []acquisition.FileCtx

	if flags.SingleFilePath != "" {
		log.Debugf("Building acquisition for %s (%s)", flags.SingleFilePath, flags.SingleFileType)
		tmpctx, err = acquisition.LoadAcquisCtxSingleFile(flags.SingleFilePath, flags.SingleFileType)
		if err != nil {
			return fmt.Errorf("Failed to load acquisition : %s", err)
		}
	} else {
		log.Debugf("Building acquisition from %s", cConfig.Crowdsec.AcquisitionFilePath)
		tmpctx, err = acquisition.LoadAcquisCtxConfigFile(cConfig.Crowdsec)
		if err != nil {
			return fmt.Errorf("Failed to load acquisition : %s", err)
		}
	}

	acquisitionCTX, err = acquisition.InitReaderFromFileCtx(tmpctx)
	if err != nil {
		return fmt.Errorf("Failed to start acquisition : %s", err)
	}
	return nil
}

func (f *Flags) Parse() {

	flag.StringVar(&f.ConfigFile, "c", "/etc/crowdsec/config.yaml", "configuration file")
	flag.BoolVar(&f.TraceLevel, "trace", false, "VERY verbose")
	flag.BoolVar(&f.DebugLevel, "debug", false, "print debug-level on stdout")
	flag.BoolVar(&f.InfoLevel, "info", false, "print info-level on stdout")
	flag.BoolVar(&f.PrintVersion, "version", false, "display version")
	flag.StringVar(&f.SingleFilePath, "file", "", "Process a single file in time-machine")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")

	flag.Parse()
}

// LoadConfig return configuration parsed from configuration file
func LoadConfig(config *csconfig.GlobalConfig) error {

	if flags.ConfigFile != "" {
		if err := config.LoadConfigurationFile(flags.ConfigFile); err != nil {
			return fmt.Errorf("while loading configuration : %s", err)
		}
	} else {
		log.Warningf("no configuration file provided")
	}
	disableAPI = flags.DisableAPI
	disableAgent = flags.DisableAgent

	if !disableAPI && (cConfig.API == nil || cConfig.API.Server == nil) {
		log.Errorf("no API server configuration found, will not start the local API")
		disableAPI = true
	}

	if !disableAgent && cConfig.Crowdsec == nil {
		log.Errorf("no configuration found crowdsec agent, will not start the agent")
		disableAgent = true
	}

	if !disableAgent && (cConfig.API == nil || cConfig.API.Client == nil || cConfig.API.Client.Credentials == nil) {
		log.Fatalf("missing local API credentials for crowdsec agent, abort")
	}

	if disableAPI && disableAgent {
		log.Fatalf("You must run at least the API Server or crowdsec")
	}

	if flags.SingleFilePath != "" {
		if flags.SingleFileType == "" {
			return fmt.Errorf("-file requires -type")
		}
	}

	if flags.DebugLevel {
		config.Common.LogLevel = log.DebugLevel
	}
	if flags.InfoLevel {
		config.Common.LogLevel = log.InfoLevel
	}
	if flags.TraceLevel {
		config.Common.LogLevel = log.TraceLevel
	}

	if flags.TestMode && !disableAgent {
		config.Crowdsec.LintOnly = true
	}

	return nil
}

func main() {
	var (
		err error
	)

	defer types.CatchPanic("crowdsec/main")

	cConfig = csconfig.NewConfig()
	// Handle command line arguments
	flags = &Flags{}
	flags.Parse()
	if flags.PrintVersion {
		cwversion.Show()
		os.Exit(0)
	}

	if err := LoadConfig(cConfig); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, cConfig.Common.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	if !flags.DisableAPI && (cConfig.API == nil || cConfig.API.Server == nil) {
		log.Errorf("no API server configuration found, will not start the local API")
		flags.DisableAPI = true
	}

	if !flags.DisableAgent && cConfig.Crowdsec == nil {
		log.Errorf("no configuration found crowdsec agent, will not start the agent")
		flags.DisableAgent = true
	}

	if !flags.DisableAgent && (cConfig.API == nil || cConfig.API.Client == nil || cConfig.API.Client.Credentials == nil) {
		log.Fatalf("missing local API credentials for crowdsec agent, abort")
	}
	// Enable profiling early
	if cConfig.Prometheus != nil {
		go registerPrometheus(cConfig.Prometheus.Level)
	}


	if err := Serve(); err != nil {
		log.Fatalf(err.Error())
	}

}
