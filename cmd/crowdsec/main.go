package main

import (
	"strings"

	"io/ioutil"

	_ "net/http/pprof"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	log "github.com/sirupsen/logrus"

	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

var (
	/*tombs for the parser, buckets and outputs.*/
	acquisTomb  tomb.Tomb
	parsersTomb tomb.Tomb
	bucketsTomb tomb.Tomb
	outputsTomb tomb.Tomb

	holders []leaky.BucketFactory
	buckets *leaky.Buckets
	cConfig *csconfig.CrowdSec

	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
)

func main() {
	var (
		err                 error
		p                   parser.UnixParser
		parserNodes         []parser.Node = make([]parser.Node, 0)
		postOverflowNodes   []parser.Node = make([]parser.Node, 0)
		nbParser            int           = 1
		parserCTX           *parser.UnixParserCtx
		postOverflowCTX     *parser.UnixParserCtx
		acquisitionCTX      *acquisition.FileAcquisCtx
		CustomParsers       []parser.Stagefile
		CustomPostoverflows []parser.Stagefile
		CustomScenarios     []parser.Stagefile
		outputEventChan     chan types.Event
	)

	inputLineChan := make(chan types.Event)
	inputEventChan := make(chan types.Event)

	cConfig = csconfig.NewCrowdSecConfig()

	// Handle command line arguments
	if err := cConfig.GetOPT(); err != nil {
		log.Fatalf(err.Error())
	}

	if err = types.SetDefaultLoggerConfig(cConfig.LogMode, cConfig.LogFolder, cConfig.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	if cConfig.Prometheus {
		registerPrometheus()
		cConfig.Profiling = true
	}

	log.Infof("Loading grok library")
	/* load base regexps for two grok parsers */
	parserCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		log.Errorf("failed to initialize parser : %v", err)
		return
	}
	postOverflowCTX, err = p.Init(map[string]interface{}{"patterns": cConfig.ConfigFolder + string("/patterns/"), "data": cConfig.DataFolder})
	if err != nil {
		log.Errorf("failed to initialize postoverflow : %v", err)
		return
	}

	/*enable profiling*/
	if cConfig.Profiling {
		go runTachymeter(cConfig.HTTPListen)
		parserCTX.Profiling = true
		postOverflowCTX.Profiling = true
	}

	/*
		Load enrichers
	*/
	log.Infof("Loading enrich plugins")
	parserPlugins, err := parser.Loadplugin(cConfig.DataFolder)
	if err != nil {
		log.Errorf("Failed to load plugin geoip : %v", err)
	}
	parser.ECTX = append(parser.ECTX, parserPlugins)

	/*parser the validatormode option if present. mostly used for testing purposes*/
	if cConfig.ValidatorMode != "" {
		//beurk : provided 'parser:file.yaml,postoverflow:file.yaml,scenario:file.yaml load only those
		validators := strings.Split(cConfig.ValidatorMode, ",")
		for _, val := range validators {
			splittedValidator := strings.Split(val, ":")
			if len(splittedValidator) != 2 {
				log.Fatalf("parser:file,scenario:file,postoverflow:file")
			}

			configType := splittedValidator[0]
			configFile := splittedValidator[1]

			var parsedFile []parser.Stagefile
			dataFile, err := ioutil.ReadFile(configFile)

			if err != nil {
				log.Fatalf("failed opening %s : %s", configFile, err)
			}
			if err := yaml.UnmarshalStrict(dataFile, &parsedFile); err != nil {
				log.Fatalf("failed unmarshalling %s : %s", configFile, err)
			}
			switch configType {
			case "parser":
				CustomParsers = parsedFile
			case "scenario":
				CustomScenarios = parsedFile
			case "postoverflow":
				CustomPostoverflows = parsedFile
			default:
				log.Fatalf("wrong type, format is parser:file,scenario:file,postoverflow:file")
			}

		}
	}

	/* load the parser nodes */
	if cConfig.ValidatorMode != "" && len(CustomParsers) > 0 {
		log.Infof("Loading (validatormode) parsers")
		parserNodes, err = parser.LoadStages(CustomParsers, parserCTX)
	} else {
		log.Infof("Loading parsers")
		parserNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/parsers/", parserCTX)
	}
	if err != nil {
		log.Fatalf("failed to load parser config : %v", err)
	}
	/* parsers loaded */

	/* load the post-overflow stages*/
	if cConfig.ValidatorMode != "" && len(CustomPostoverflows) > 0 {
		log.Infof("Loading (validatormode) postoverflow parsers")
		postOverflowNodes, err = parser.LoadStages(CustomPostoverflows, postOverflowCTX)
	} else {
		log.Infof("Loading postoverflow parsers")
		postOverflowNodes, err = parser.LoadStageDir(cConfig.ConfigFolder+"/postoverflows/", postOverflowCTX)
	}
	if err != nil {
		log.Fatalf("failed to load postoverflow config : %v", err)
	}

	log.Infof("Loaded Nodes : %d parser, %d postoverflow", len(parserNodes), len(postOverflowNodes))
	/* post overflow loaded */

	/* Loading buckets / scenarios */
	if cConfig.ValidatorMode != "" && len(CustomScenarios) > 0 {
		log.Infof("Loading (validatormode) scenarios")
		bucketFiles := []string{}
		for _, scenarios := range CustomScenarios {
			bucketFiles = append(bucketFiles, scenarios.Filename)
		}
		holders, outputEventChan, err = leaky.LoadBuckets(bucketFiles, cConfig.DataFolder)

	} else {
		log.Infof("Loading scenarios")
		holders, outputEventChan, err = leaky.Init(map[string]string{"patterns": cConfig.ConfigFolder + "/scenarios/", "data": cConfig.DataFolder})
	}
	if err != nil {
		log.Fatalf("Scenario loading failed : %v", err)
	}
	/* buckets/scenarios loaded */

	/*keep track of scenarios name for consensus profiling*/
	var scenariosEnabled string
	for _, x := range holders {
		if scenariosEnabled != "" {
			scenariosEnabled += ","
		}
		scenariosEnabled += x.Name
	}

	buckets = leaky.NewBuckets()

	/*restore as well previous state if present*/
	if cConfig.RestoreMode != "" {
		log.Warningf("Restoring buckets state from %s", cConfig.RestoreMode)
		if err := leaky.LoadBucketsState(cConfig.RestoreMode, buckets, holders); err != nil {
			log.Fatalf("unable to restore buckets : %s", err)
		}
	}
	if cConfig.Profiling {
		//force the profiling in all buckets
		for holderIndex := range holders {
			holders[holderIndex].Profiling = true
		}
	}

	/*
		Load output profiles
	*/
	log.Infof("Loading output profiles")
	outputProfiles, err := outputs.LoadOutputProfiles(cConfig.ConfigFolder + "/profiles.yaml")
	if err != nil || len(outputProfiles) == 0 {
		log.Fatalf("Failed to load output profiles : %v", err)
	}
	/* Linting is done */
	if cConfig.Linter {
		return
	}

	outputRunner, err := outputs.NewOutput(cConfig.OutputConfig, cConfig.Daemonize)
	if err != nil {
		log.Fatalf("output plugins initialization error : %s", err.Error())
	}

	/* Init the API connector */
	if cConfig.APIMode {
		log.Infof("Loading API client")
		var apiConfig = map[string]string{
			"path":    cConfig.ConfigFolder + "/api.yaml",
			"profile": scenariosEnabled,
		}
		if err := outputRunner.InitAPI(apiConfig); err != nil {
			log.Fatalf(err.Error())
		}
	}

	/*if the user is in "single file mode" (might be writting scenario or parsers), allow loading **without** parsers or scenarios */
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

	log.Infof("Starting processing routines")
	//start go-routines for parsing, buckets pour and ouputs.
	for i := 0; i < nbParser; i++ {
		parsersTomb.Go(func() error {
			err := runParse(inputLineChan, inputEventChan, *parserCTX, parserNodes)
			if err != nil {
				log.Errorf("runParse error : %s", err)
				return err
			}
			return nil
		})
	}

	for i := 0; i < nbParser; i++ {
		bucketsTomb.Go(func() error {
			err := runPour(inputEventChan, holders, buckets)
			if err != nil {
				log.Errorf("runPour error : %s", err)
				return err
			}
			return nil
		})
	}

	for i := 0; i < nbParser; i++ {
		outputsTomb.Go(func() error {
			err := runOutput(inputEventChan, outputEventChan, holders, buckets, *postOverflowCTX, postOverflowNodes, outputProfiles, outputRunner)
			if err != nil {
				log.Errorf("runPour error : %s", err)
				return err
			}
			return nil
		})
	}

	log.Warningf("Starting processing data")

	//Init the acqusition : from cli or from acquis.yaml file
	acquisitionCTX, err = acquisition.LoadAcquisitionConfig(cConfig)
	if err != nil {
		log.Fatalf("Failed to start acquisition : %s", err)
	}
	//start reading in the background
	acquisition.AcquisStartReading(acquisitionCTX, inputLineChan, &acquisTomb)

	if err = serve(*outputRunner); err != nil {
		log.Fatalf(err.Error())
	}

}
