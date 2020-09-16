package main

import (
	"fmt"
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
	cConfig *csconfig.CrowdSec
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
		for _, hubParserItem := range cwhub.HubIdx[itemType] {
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

func LoadParsers(cConfig *csconfig.CrowdSec, parsers *parsers) (*parsers, error) {
	var err error

	log.Infof("Loading grok library")
	/* load base regexps for two grok parsers */
	parsers.ctx, err = parser.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		return parsers, fmt.Errorf("failed to load parser patterns : %v", err)
	}
	parsers.povfwctx, err = parser.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		return parsers, fmt.Errorf("failed to load postovflw parser patterns : %v", err)
	}

	/*
		Load enrichers
	*/
	log.Infof("Loading enrich plugins")
	parsers.enricherCtx, err = parser.Loadplugin(cConfig.DataFolder)
	if err != nil {
		return parsers, fmt.Errorf("Failed to load enrich plugin : %v", err)
	}

	/*
	 Load the actual parsers
	*/

	log.Infof("Loading parsers")

	parsers.nodes, err = parser.LoadStages(parsers.stageFiles, parsers.ctx, parsers.enricherCtx)
	if err != nil {
		return parsers, fmt.Errorf("failed to load parser config : %v", err)
	}

	log.Infof("Loading postoverflow parsers") //cConfig.ConfigFolder+"/postoverflows/"
	parsers.povfwnodes, err = parser.LoadStages(parsers.povfwStageFiles, parsers.povfwctx, parsers.enricherCtx)

	if err != nil {
		return parsers, fmt.Errorf("failed to load postoverflow config : %v", err)
	}

	if cConfig.Profiling {
		parsers.ctx.Profiling = true
		parsers.povfwctx.Profiling = true
	}

	return parsers, nil
}

func LoadBuckets(cConfig *csconfig.CrowdSec) error {

	var (
		err   error
		files []string
	)
	for _, hubScenarioItem := range cwhub.HubIdx[cwhub.SCENARIOS] {
		files = append(files, hubScenarioItem.LocalPath)
	}

	log.Infof("Loading scenarios")
	holders, outputEventChan, err = leaky.LoadBuckets(*cConfig, files)

	if err != nil {
		return fmt.Errorf("Scenario loading failed : %v", err)
	}
	buckets = leaky.NewBuckets()

	/*restore as well previous state if present*/
	if cConfig.RestoreMode != "" {
		log.Warningf("Restoring buckets state from %s", cConfig.RestoreMode)
		if err := leaky.LoadBucketsState(cConfig.RestoreMode, buckets, holders); err != nil {
			return fmt.Errorf("unable to restore buckets : %s", err)
		}
	}
	if cConfig.Profiling {
		for holderIndex := range holders {
			holders[holderIndex].Profiling = true
		}
	}
	return nil
}

func LoadAcquisition(cConfig *csconfig.CrowdSec) error {
	var err error
	//Init the acqusition : from cli or from acquis.yaml file
	acquisitionCTX, err = acquisition.LoadAcquisitionConfig(cConfig)
	if err != nil {
		return fmt.Errorf("Failed to start acquisition : %s", err)
	}
	return nil
}

func StartProcessingRoutines(cConfig *csconfig.CrowdSec, parsers *parsers) (chan types.Event, error) {

	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}

	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	//start go-routines for parsing, buckets pour and ouputs.
	for i := 0; i < cConfig.NbParsers; i++ {
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
		err := runOutput(inputEventChan, outputEventChan, holders, buckets, *parsers.povfwctx, parsers.povfwnodes)
		if err != nil {
			log.Errorf("runPour error : %s", err)
			return err
		}
		return nil
	})

	return inputLineChan, nil
}

func main() {
	var (
		err error
	)

	cConfig = csconfig.NewCrowdSecConfig()

	// Handle command line arguments
	if err := cConfig.LoadConfig(); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.LogMode, cConfig.LogFolder, cConfig.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	daemonCTX := &daemon.Context{
		PidFileName: cConfig.PIDFolder + "/crowdsec.pid",
		PidFilePerm: 0644,
		WorkDir:     "./",
		Umask:       027,
	}
	if cConfig.Daemonize {
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
	if cConfig.Prometheus {
		registerPrometheus(cConfig.PrometheusMode)
		cConfig.Profiling = true
	}
	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("Failed to init expr helpers : %s", err)
	}

	// Populate cwhub package tools
	cwhub.Cfgdir = cConfig.ConfigFolder
	cwhub.GetHubIdx()
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
	if cConfig.Linter {
		return
	}

	/*if the user is in "single file mode" (might be writting scenario or parsers),
	allow loading **without** parsers or scenarios */
	if cConfig.SingleFile == "" {
		if len(parsers.nodes) == 0 {
			log.Fatalf("no parser(s) loaded, abort.")
		}

		if len(holders) == 0 {
			log.Fatalf("no bucket(s) loaded, abort.")
		}
	}

	//Start the background routines that comunicate via chan
	log.Infof("Starting processing routines")
	inputLineChan, err := StartProcessingRoutines(cConfig, parsers)
	if err != nil {
		log.Fatalf("failed to start processing routines : %s", err)
	}

	//Fire!
	log.Warningf("Starting processing data")

	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	if !cConfig.Daemonize {
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
