package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	_ "net/http/pprof"
	"time"

	"github.com/confluentinc/bincover"
	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"

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
	pluginTomb   tomb.Tomb

	flags *Flags

	/*the state of acquisition*/
	dataSources []acquisition.DataSource
	/*the state of the buckets*/
	holders         []leaky.BucketFactory
	buckets         *leaky.Buckets
	outputEventChan chan types.Event //the buckets init returns its own chan that is used for multiplexing
	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
	pluginBroker      csplugin.PluginBroker
)

const bincoverTesting = false

type Flags struct {
	ConfigFile     string
	TraceLevel     bool
	DebugLevel     bool
	InfoLevel      bool
	PrintVersion   bool
	SingleFileType string
	Labels         map[string]string
	OneShotDSN     string
	TestMode       bool
	DisableAgent   bool
	DisableAPI     bool
}

type labelsMap map[string]string

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
		sort.Slice(parsers.StageFiles, func(i, j int) bool {
			return parsers.StageFiles[i].Filename < parsers.StageFiles[j].Filename
		})
	}
	if parsers.PovfwStageFiles != nil {
		sort.Slice(parsers.PovfwStageFiles, func(i, j int) bool {
			return parsers.PovfwStageFiles[i].Filename < parsers.PovfwStageFiles[j].Filename
		})
	}

	return parsers
}

func LoadBuckets(cConfig *csconfig.Config) error {

	var (
		err   error
		files []string
	)
	for _, hubScenarioItem := range cwhub.GetItemMap(cwhub.SCENARIOS) {
		if hubScenarioItem.Installed {
			files = append(files, hubScenarioItem.LocalPath)
		}
	}
	buckets = leaky.NewBuckets()

	log.Infof("Loading %d scenario files", len(files))
	holders, outputEventChan, err = leaky.LoadBuckets(cConfig.Crowdsec, files, &bucketsTomb, buckets)

	if err != nil {
		return fmt.Errorf("Scenario loading failed : %v", err)
	}

	if cConfig.Prometheus != nil && cConfig.Prometheus.Enabled {
		for holderIndex := range holders {
			holders[holderIndex].Profiling = true
		}
	}
	return nil
}

func LoadAcquisition(cConfig *csconfig.Config) error {
	var err error

	if flags.SingleFileType != "" || flags.OneShotDSN != "" {
		if flags.OneShotDSN == "" || flags.SingleFileType == "" {
			return fmt.Errorf("-type requires a -dsn argument")
		}
		flags.Labels = labels
		flags.Labels["type"] = flags.SingleFileType

		dataSources, err = acquisition.LoadAcquisitionFromDSN(flags.OneShotDSN, flags.Labels)
		if err != nil {
			return errors.Wrapf(err, "failed to configure datasource for %s", flags.OneShotDSN)
		}
	} else {
		dataSources, err = acquisition.LoadAcquisitionFromFile(cConfig.Crowdsec)
		if err != nil {
			return errors.Wrap(err, "while loading acquisition configuration")
		}
	}

	return nil
}

var dumpFolder string
var dumpStates bool
var labels = make(labelsMap)

func (l *labelsMap) String() string {
	return "labels"
}

func (l labelsMap) Set(label string) error {
	split := strings.Split(label, ":")
	if len(split) != 2 {
		return errors.Wrapf(errors.New("Bad Format"), "for Label '%s'", label)
	}
	l[split[0]] = split[1]
	return nil
}

func (f *Flags) Parse() {

	flag.StringVar(&f.ConfigFile, "c", csconfig.DefaultConfigPath("config.yaml"), "configuration file")
	flag.BoolVar(&f.TraceLevel, "trace", false, "VERY verbose")
	flag.BoolVar(&f.DebugLevel, "debug", false, "print debug-level on stdout")
	flag.BoolVar(&f.InfoLevel, "info", false, "print info-level on stdout")
	flag.BoolVar(&f.PrintVersion, "version", false, "display version")
	flag.StringVar(&f.OneShotDSN, "dsn", "", "Process a single data source in time-machine")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.Var(&labels, "label", "Additional Labels for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")
	flag.StringVar(&dumpFolder, "dump-data", "", "dump parsers/buckets raw outputs")

	flag.Parse()
}

// LoadConfig returns a configuration parsed from configuration file
func LoadConfig(cConfig *csconfig.Config) error {

	if dumpFolder != "" {
		parser.ParseDump = true
		parser.DumpFolder = dumpFolder
		leakybucket.BucketPourTrack = true
		dumpStates = true
	}

	if !flags.DisableAgent {
		if err := cConfig.LoadCrowdsec(); err != nil {
			return err
		}
	}

	if !flags.DisableAPI {
		if err := cConfig.LoadAPIServer(); err != nil {
			return err
		}
	}

	if !cConfig.DisableAgent && (cConfig.API == nil || cConfig.API.Client == nil || cConfig.API.Client.Credentials == nil) {
		log.Fatalf("missing local API credentials for crowdsec agent, abort")
	}

	if cConfig.DisableAPI && cConfig.DisableAgent {
		log.Fatalf("You must run at least the API Server or crowdsec")
	}

	if flags.DebugLevel {
		logLevel := log.DebugLevel
		cConfig.Common.LogLevel = &logLevel
	}
	if flags.InfoLevel || cConfig.Common.LogLevel == nil {
		logLevel := log.InfoLevel
		cConfig.Common.LogLevel = &logLevel
	}
	if flags.TraceLevel {
		logLevel := log.TraceLevel
		cConfig.Common.LogLevel = &logLevel
	}

	if flags.TestMode && !cConfig.DisableAgent {
		cConfig.Crowdsec.LintOnly = true
	}

	if flags.SingleFileType != "" && flags.OneShotDSN != "" {
		if cConfig.API != nil && cConfig.API.Server != nil {
			cConfig.API.Server.OnlineClient = nil
		}
		/*if the api is disabled as well, just read file and exit, don't daemonize*/
		if flags.DisableAPI {
			cConfig.Common.Daemonize = false
		}
		cConfig.Common.LogMedia = "stdout"
		log.Infof("single file mode : log_media=%s daemonize=%t", cConfig.Common.LogMedia, cConfig.Common.Daemonize)
	}

	if cConfig.Common.PidDir != "" {
		log.Warn("Deprecation warning: the pid_dir config can be safely removed and is not required")
	}

	return nil
}

func main() {
	var (
		cConfig *csconfig.Config
		err     error
	)

	defer types.CatchPanic("crowdsec/main")

	log.Debugf("os.Args: %v", os.Args)

	// Handle command line arguments
	flags = &Flags{}
	flags.Parse()
	if flags.PrintVersion {
		cwversion.Show()
		os.Exit(0)
	}
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
			log.Errorf(err.Error())
			if !bincoverTesting {
				os.Exit(exitCode)
			}
			bincover.ExitCode = exitCode
		}
	}
}
