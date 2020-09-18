package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	_ "net/http/pprof"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/sevlyar/go-daemon"

	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
)

var (
	/*tombs for the parser, buckets and outputs.*/
	acquisTomb  tomb.Tomb
	parsersTomb tomb.Tomb
	bucketsTomb tomb.Tomb
	outputsTomb tomb.Tomb
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
func newParsers() *parsers {
	parsers := &parsers{
		ctx:             &parser.UnixParserCtx{},
		povfwctx:        &parser.UnixParserCtx{},
		stageFiles:      make([]parser.Stagefile, 0),
		povfwStageFiles: make([]parser.Stagefile, 0),
	}
	for _, itemType := range []string{cwhub.PARSERS, cwhub.PARSERS_OVFLW} {
		for _, hubParserItem := range cwhub.GetItemMap(itemType) {
			if hubParserItem.Installed {
				stagefile := parser.Stagefile{
					Filename: hubParserItem.LocalPath,
					Stage:    hubParserItem.Stage,
				}
				if itemType == cwhub.PARSERS {
					parsers.stageFiles = append(parsers.stageFiles, stagefile)
				}
				if itemType == cwhub.PARSERS_OVFLW {
					parsers.povfwStageFiles = append(parsers.povfwStageFiles, stagefile)
				}
			}
		}
	}
	return parsers
}

func LoadParsers(cConfig *csconfig.GlobalConfig, parsers *parsers) (*parsers, error) {
	var err error

	log.Infof("Loading grok library %s", cConfig.Crowdsec.ConfigDir+string("/patterns/"))
	/* load base regexps for two grok parsers */
	parsers.ctx, err = parser.Init(map[string]interface{}{"patterns": cConfig.Crowdsec.ConfigDir + string("/patterns/"),
		"data": cConfig.Crowdsec.DataDir})
	if err != nil {
		return parsers, fmt.Errorf("failed to load parser patterns : %v", err)
	}
	parsers.povfwctx, err = parser.Init(map[string]interface{}{"patterns": cConfig.Crowdsec.ConfigDir + string("/patterns/"),
		"data": cConfig.Crowdsec.DataDir})
	if err != nil {
		return parsers, fmt.Errorf("failed to load postovflw parser patterns : %v", err)
	}

	/*
		Load enrichers
	*/
	log.Infof("Loading enrich plugins")

	parsers.enricherCtx, err = parser.Loadplugin(cConfig.Crowdsec.DataDir)
	if err != nil {
		return parsers, fmt.Errorf("Failed to load enrich plugin : %v", err)
	}

	/*
	 Load the actual parsers
	*/

	log.Infof("Loading parsers %d stages", len(parsers.stageFiles))

	parsers.nodes, err = parser.LoadStages(parsers.stageFiles, parsers.ctx, parsers.enricherCtx)
	if err != nil {
		return parsers, fmt.Errorf("failed to load parser config : %v", err)
	}

	log.Infof("Loading postoverflow parsers")
	parsers.povfwnodes, err = parser.LoadStages(parsers.povfwStageFiles, parsers.povfwctx, parsers.enricherCtx)

	if err != nil {
		return parsers, fmt.Errorf("failed to load postoverflow config : %v", err)
	}

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		parsers.ctx.Profiling = true
		parsers.povfwctx.Profiling = true
	}

	return parsers, nil
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

	log.Infof("Loading %d scenarios", len(files))
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

	if *SingleFilePath != "" {
		log.Debugf("Building acquisition for %s (%s)", *SingleFilePath, *SingleFileType)
		tmpctx, err = acquisition.LoadAcquisCtxSingleFile(*SingleFilePath, *SingleFileType)
		if err != nil {
			return fmt.Errorf("Failed to load acquisition : %s", err)
		}
	} else {
		log.Debugf("Building acquisition from %s", cConfig.Crowdsec.AcquisitionFilePath)
		tmpctx, err = acquisition.LoadAcquisCtxConfigFile(cConfig)
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

func StartProcessingRoutines(cConfig *csconfig.GlobalConfig, parsers *parsers) (chan types.Event, error) {

	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}

	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	//start go-routines for parsing, buckets pour and ouputs.
	for i := 0; i < cConfig.Crowdsec.ParserRoutinesCount; i++ {
		parsersTomb.Go(func() error {
			err := runParse(inputLineChan, inputEventChan, *parsers.ctx, parsers.nodes)
			if err != nil {
				log.Errorf("runParse error : %s", err)
				return err
			}
			return nil
		})
	}

	bucketsTomb.Go(func() error {
		err := runPour(inputEventChan, holders, buckets)
		if err != nil {
			log.Errorf("runPour error : %s", err)
			return err
		}
		return nil
	})

	outputsTomb.Go(func() error {
		err := runOutput(inputEventChan, outputEventChan, buckets, *parsers.povfwctx, parsers.povfwnodes, *cConfig.ApiClient.Credentials)
		if err != nil {
			log.Errorf("runPour error : %s", err)
			return err
		}
		return nil
	})

	return inputLineChan, nil
}

var SingleFilePath, SingleFileType *string

// LoadConfig return configuration parsed from command line and configuration file
func LoadConfig(config *csconfig.GlobalConfig) error {
	configFile := flag.String("c", "/etc/crowdsec/config/default.yaml", "configuration file")
	printTrace := flag.Bool("trace", false, "VERY verbose")
	printDebug := flag.Bool("debug", false, "print debug-level on stdout")
	printInfo := flag.Bool("info", false, "print info-level on stdout")
	printVersion := flag.Bool("version", false, "display version")
	SingleFilePath = flag.String("file", "", "Process a single file in time-machine")
	SingleFileType = flag.String("type", "", "Labels.type for file in time-machine")
	testMode := flag.Bool("t", false, "only test configs")
	flag.Parse()
	if *printVersion {
		cwversion.Show()
		os.Exit(0)
	}

	if configFile != nil {
		if err := config.LoadConfigurationFile(*configFile); err != nil {
			return fmt.Errorf("Error while loading configuration : %s", err)
		}
	} else {
		log.Warningf("no configuration file provided")
	}

	if *SingleFilePath != "" {
		if *SingleFileType == "" {
			return fmt.Errorf("-file requires -type")
		}

	}

	if *printDebug {
		config.Daemon.LogLevel = log.DebugLevel
	}
	if *printInfo {
		config.Daemon.LogLevel = log.InfoLevel
	}
	if *printTrace {
		config.Daemon.LogLevel = log.TraceLevel
	}

	if *testMode {
		config.Crowdsec.LintOnly = true
	}

	return nil
}

func main() {
	var (
		err error
	)

	cConfig = csconfig.NewConfig()
	// Handle command line arguments
	if err := LoadConfig(cConfig); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Daemon.LogMedia, cConfig.Daemon.LogDir, cConfig.Daemon.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	daemonCTX := &daemon.Context{
		PidFileName: cConfig.Daemon.PidDir + "/crowdsec.pid",
		PidFilePerm: 0644,
		WorkDir:     "./",
		Umask:       027,
	}
	if cConfig.Daemon.Daemonize {
		daemon.SetSigHandler(termHandler, syscall.SIGTERM)
		daemon.SetSigHandler(reloadHandler, syscall.SIGHUP)
		daemon.SetSigHandler(debugHandler, syscall.SIGUSR1)

		d, err := daemonCTX.Reborn()
		if err != nil {
			log.Fatalf("unable to run daemon: %s ", err.Error())
		}
		if d != nil {
			return
		}
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	// Enable profiling early
	if cConfig.Prometheus != nil {
		registerPrometheus(cConfig.Prometheus.Level)
	}
	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("Failed to init expr helpers : %s", err)
	}

	// Populate cwhub package tools

	if err := cwhub.GetHubIdx(cConfig.Cscli); err != nil {
		log.Fatalf("Failed to load hub index : %s", err)
	}

	// Start loading configs
	parsers := newParsers()
	if parsers, err = LoadParsers(cConfig, parsers); err != nil {
		log.Fatalf("Failed to load parsers: %s", err)
	}

	if err := LoadBuckets(cConfig); err != nil {
		log.Fatalf("Failed to load scenarios: %s", err)
	}

	if err := LoadAcquisition(cConfig); err != nil {
		log.Fatalf("Error while loading acquisition config : %s", err)
	}

	/* if it's just linting, we're done */
	if cConfig.Crowdsec.LintOnly {
		log.Infof("lint done")
		return
	}

	/*TBD : need to be cleaned up a bit*/
	/*if the user is in "single file mode" (might be writting scenario or parsers),
	allow loading **without** parsers or scenarios */
	// if cConfig.SingleFile == "" {
	// 	if len(parsers.nodes) == 0 {
	// 		log.Fatalf("no parser(s) loaded, abort.")
	// 	}

	// 	if len(holders) == 0 {
	// 		log.Fatalf("no bucket(s) loaded, abort.")
	// 	}
	// }

	//Start the background routines that comunicate via chan
	log.Infof("Starting processing routines")
	inputLineChan, err := StartProcessingRoutines(cConfig, parsers)
	if err != nil {
		log.Fatalf("failed to start processing routines : %s", err)
	}

	//Fire!
	log.Warningf("Starting processing data")

	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	if cConfig.Daemon != nil {
		if err = serveOneTimeRun(); err != nil {
			log.Errorf(err.Error())
		} else {
			return
		}
	} else {
		defer daemonCTX.Release() //nolint:errcheck // won't bother checking this error in defer statement
		err = daemon.ServeSignals()
		if err != nil {
			log.Fatalf("serveDaemon error : %s", err.Error())
		}
	}
}
