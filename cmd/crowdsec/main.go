package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
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

var bincoverTesting = ""

type Flags struct {
	ConfigFile     string
	TraceLevel     bool
	DebugLevel     bool
	InfoLevel      bool
	WarnLevel      bool
	PrintVersion   bool
	SingleFileType string
	Labels         map[string]string
	OneShotDSN     string
	TestMode       bool
	DisableAgent   bool
	DisableAPI     bool
	WinSvc         string
	DisableCAPI    bool
	LogMedia       string
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
	flag.BoolVar(&f.DebugLevel, "debug", false, "print debug-level on stderr")
	flag.BoolVar(&f.InfoLevel, "info", false, "print info-level on stderr")
	flag.BoolVar(&f.WarnLevel, "warning", false, "print warning-level on stderr")
	flag.BoolVar(&f.PrintVersion, "version", false, "display version")
	flag.StringVar(&f.OneShotDSN, "dsn", "", "Process a single data source in time-machine")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.Var(&labels, "label", "Additional Labels for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")
	flag.BoolVar(&f.DisableCAPI, "no-capi", false, "disable communication with Central API")
	flag.StringVar(&f.WinSvc, "winsvc", "", "Windows service Action : Install, Remove etc..")
	flag.StringVar(&dumpFolder, "dump-data", "", "dump parsers/buckets raw outputs")
	flag.StringVar(&f.LogMedia, "log-media", "", "log media output")
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
		return errors.New("missing local API credentials for crowdsec agent, abort")
	}

	if cConfig.DisableAPI && cConfig.DisableAgent {
		return errors.New("You must run at least the API Server or crowdsec")
	}

	if flags.WarnLevel {
		logLevel := log.WarnLevel
		cConfig.Common.LogLevel = &logLevel
	}
	if flags.InfoLevel || cConfig.Common.LogLevel == nil {
		logLevel := log.InfoLevel
		cConfig.Common.LogLevel = &logLevel
	}
	if flags.DebugLevel {
		logLevel := log.DebugLevel
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

	if flags.LogMedia != "" {
		cConfig.Common.LogMedia = strings.ToLower(flags.LogMedia)
	}

	if cConfig.Common.PidDir != "" {
		log.Warn("Deprecation warning: the pid_dir config can be safely removed and is not required")
	}

	if cConfig.Common.Daemonize && runtime.GOOS == "windows" {
		log.Debug("Daemonization is not supported on Windows, disabling")
		cConfig.Common.Daemonize = false
	}

	return nil
}

// exitWithCode must be called right before the program termination,
// to allow measuring functional test coverage in case of abnormal exit.
//
// without bincover: log error and exit with code
// with bincover: log error and tell bincover the exit code, then return
func exitWithCode(exitCode int, err error) {
	if err != nil {
		// this method of logging a fatal error does not
		// trigger a program exit (as stated by the authors, it
		// is not going to change in logrus to keep backward
		// compatibility), and allows us to report coverage.
		log.NewEntry(log.StandardLogger()).Log(log.FatalLevel, err)
	}
	if bincoverTesting == "" {
		os.Exit(exitCode)
	}
	bincover.ExitCode = exitCode
}

// crowdsecT0 can be used to measure start time of services,
// or uptime of the application
var crowdsecT0 time.Time

func main() {
	crowdsecT0 = time.Now()

	defer types.CatchPanic("crowdsec/main")

	log.Debugf("os.Args: %v", os.Args)

	// Handle command line arguments
	flags = &Flags{}
	flags.Parse()

	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "argument provided but not defined: %s\n", flag.Args()[0])
		flag.Usage()
		// the flag package exits with 2 in case of unknown flag
		exitWithCode(2, nil)
		return
	}

	if flags.PrintVersion {
		cwversion.Show()
		exitWithCode(0, nil)
		return
	}

	exitCode := 0
	err := StartRunSvc()
	if err != nil {
		exitCode = 1
	}
	exitWithCode(exitCode, err)
}
