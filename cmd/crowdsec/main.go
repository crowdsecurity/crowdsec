package main

import (
	"fmt"
	"syscall"

	_ "net/http/pprof"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"
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
	/*the state of outputs*/
	OutputRunner   *outputs.Output
	outputProfiles []types.Profile
	/*the state of the parsers*/
	parserCTX         *parser.UnixParserCtx
	postOverflowCTX   *parser.UnixParserCtx
	parserNodes       []parser.Node
	postOverflowNodes []parser.Node
	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
)

func LoadParsers(cConfig *csconfig.CrowdSec) error {
	var p parser.UnixParser
	var err error

	parserNodes = make([]parser.Node, 0)
	postOverflowNodes = make([]parser.Node, 0)

	log.Infof("Loading grok library")
	/* load base regexps for two grok parsers */
	parserCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		return fmt.Errorf("failed to load parser patterns : %v", err)
	}
	postOverflowCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		return fmt.Errorf("failed to load postovflw parser patterns : %v", err)
	}

	/*
		Load enrichers
	*/
	log.Infof("Loading enrich plugins")
	parserPlugins, err := parser.Loadplugin(cConfig.DataFolder)
	if err != nil {
		return fmt.Errorf("Failed to load enrich plugin : %v", err)
	}
	parser.ECTX = []parser.EnricherCtx{parserPlugins}

	/*
	 Load the actual parsers
	*/

	log.Infof("Loading parsers")
	parserNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/parsers/", parserCTX)

	if err != nil {
		return fmt.Errorf("failed to load parser config : %v", err)
	}

	log.Infof("Loading postoverflow parsers")
	postOverflowNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/postoverflows/", postOverflowCTX)

	if err != nil {
		return fmt.Errorf("failed to load postoverflow config : %v", err)
	}

	if cConfig.Profiling {
		parserCTX.Profiling = true
		postOverflowCTX.Profiling = true
	}

	return nil
}

func GetEnabledScenarios() string {
	/*keep track of scenarios name for consensus profiling*/
	var scenariosEnabled string
	for _, x := range holders {
		if scenariosEnabled != "" {
			scenariosEnabled += ","
		}
		scenariosEnabled += x.Name
	}
	return scenariosEnabled
}

func LoadBuckets(cConfig *csconfig.CrowdSec) error {

	var err error

	log.Infof("Loading scenarios")
	holders, outputEventChan, err = leaky.Init(map[string]string{"patterns": cConfig.ConfigFolder + "/scenarios/", "data": cConfig.DataFolder})

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

func LoadOutputs(cConfig *csconfig.CrowdSec) error {
	var err error
	/*
		Load output profiles
	*/
	log.Infof("Loading output profiles")
	outputProfiles, err = outputs.LoadOutputProfiles(cConfig.ConfigFolder + "/profiles.yaml")
	if err != nil || len(outputProfiles) == 0 {
		return fmt.Errorf("Failed to load output profiles : %v", err)
	}

	//If the user is providing a single file (ie forensic mode), don't flush expired records
	if cConfig.SingleFile != "" {
		log.Infof("forensic mode, disable flush")
		cConfig.OutputConfig.Flush = false
	} else {
		cConfig.OutputConfig.Flush = true
	}
	OutputRunner, err = outputs.NewOutput(cConfig.OutputConfig)
	if err != nil {
		return fmt.Errorf("output plugins initialization error : %s", err.Error())
	}

	if err := OutputRunner.StartAutoCommit(); err != nil {
		return errors.Wrap(err, "failed to start autocommit")
	}

	/* Init the API connector */
	if cConfig.APIMode {
		log.Infof("Loading API client")
		var apiConfig = map[string]string{
			"path":    cConfig.ConfigFolder + "/api.yaml",
			"profile": GetEnabledScenarios(),
		}
		if err := OutputRunner.InitAPI(apiConfig); err != nil {
			return fmt.Errorf("failed to load api : %s", err)
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

func StartProcessingRoutines(cConfig *csconfig.CrowdSec) (chan types.Event, error) {

	acquisTomb = tomb.Tomb{}
	parsersTomb = tomb.Tomb{}
	bucketsTomb = tomb.Tomb{}
	outputsTomb = tomb.Tomb{}

	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	//start go-routines for parsing, buckets pour and ouputs.
	for i := 0; i < cConfig.NbParsers; i++ {
		parsersTomb.Go(func() error {
			err := runParse(inputLineChan, inputEventChan, *parserCTX, parserNodes)
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
		err := runOutput(inputEventChan, outputEventChan, holders, buckets, *postOverflowCTX, postOverflowNodes, outputProfiles, OutputRunner)
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
	if cConfig.Profiling {
		go runTachymeter(cConfig.HTTPListen)
	}

	err = exprhelpers.Init()
	if err != nil {
		log.Fatalf("Failed to init expr helpers : %s", err)
	}

	// Start loading configs
	if err := LoadParsers(cConfig); err != nil {
		log.Fatalf("Failed to load parsers: %s", err)
	}

	if err := LoadBuckets(cConfig); err != nil {
		log.Fatalf("Failed to load scenarios: %s", err)
	}

	if err := LoadOutputs(cConfig); err != nil {
		log.Fatalf("failed to initialize outputs : %s", err)
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
		if len(parserNodes) == 0 {
			log.Fatalf("no parser(s) loaded, abort.")
		}

		if len(holders) == 0 {
			log.Fatalf("no bucket(s) loaded, abort.")
		}

		if len(outputProfiles) == 0 {
			log.Fatalf("no output profile(s) loaded, abort.")
		}
	}

	//Start the background routines that comunicate via chan
	log.Infof("Starting processing routines")
	inputLineChan, err := StartProcessingRoutines(cConfig)
	if err != nil {
		log.Fatalf("failed to start processing routines : %s", err)
	}

	//Fire!
	log.Warningf("Starting processing data")

	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	if !cConfig.Daemonize {
		if err = serveOneTimeRun(*OutputRunner); err != nil {
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
