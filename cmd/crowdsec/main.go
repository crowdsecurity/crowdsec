package main

import (
	"flag"
	"fmt"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/csplugin"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/fflag"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
	holders []leakybucket.BucketFactory
	buckets *leakybucket.Buckets

	inputLineChan   chan types.Event
	inputEventChan  chan types.Event
	outputEventChan chan types.Event // the buckets init returns its own chan that is used for multiplexing
	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
	pluginBroker      csplugin.PluginBroker
)

type Flags struct {
	ConfigFile string

	LogLevelTrace bool
	LogLevelDebug bool
	LogLevelInfo  bool
	LogLevelWarn  bool
	LogLevelError bool
	LogLevelFatal bool

	PrintVersion   bool
	SingleFileType string
	Labels         map[string]string
	OneShotDSN     string
	TestMode       bool
	DisableAgent   bool
	DisableAPI     bool
	WinSvc         string
	DisableCAPI    bool
	Transform      string
	OrderEvent     bool
}

type labelsMap map[string]string

func LoadBuckets(cConfig *csconfig.Config, hub *cwhub.Hub) error {
	var (
		err   error
		files []string
	)
	for _, hubScenarioItem := range hub.GetItemMap(cwhub.SCENARIOS) {
		if hubScenarioItem.State.Installed {
			files = append(files, hubScenarioItem.State.LocalPath)
		}
	}
	buckets = leakybucket.NewBuckets()

	log.Infof("Loading %d scenario files", len(files))
	holders, outputEventChan, err = leakybucket.LoadBuckets(cConfig.Crowdsec, hub, files, &bucketsTomb, buckets, flags.OrderEvent)

	if err != nil {
		return fmt.Errorf("scenario loading failed: %v", err)
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

	if flags.SingleFileType != "" && flags.OneShotDSN != "" {
		flags.Labels = labels
		flags.Labels["type"] = flags.SingleFileType

		dataSources, err = acquisition.LoadAcquisitionFromDSN(flags.OneShotDSN, flags.Labels, flags.Transform)
		if err != nil {
			return errors.Wrapf(err, "failed to configure datasource for %s", flags.OneShotDSN)
		}
	} else {
		dataSources, err = acquisition.LoadAcquisitionFromFile(cConfig.Crowdsec)
		if err != nil {
			return err
		}
	}

	if len(dataSources) == 0 {
		return fmt.Errorf("no datasource enabled")
	}

	return nil
}

var (
	dumpFolder string
	dumpStates bool
	labels     = make(labelsMap)
)

func (l *labelsMap) String() string {
	return "labels"
}

func (l labelsMap) Set(label string) error {
	for _, pair := range strings.Split(label, ",") {
		split := strings.Split(pair, ":")
		if len(split) != 2 {
			return fmt.Errorf("invalid format for label '%s', must be key:value", pair)
		}
		l[split[0]] = split[1]
	}
	return nil
}

func (f *Flags) Parse() {
	flag.StringVar(&f.ConfigFile, "c", csconfig.DefaultConfigPath("config.yaml"), "configuration file")

	flag.BoolVar(&f.LogLevelTrace, "trace", false, "set log level to 'trace' (VERY verbose)")
	flag.BoolVar(&f.LogLevelDebug, "debug", false, "set log level to 'debug'")
	flag.BoolVar(&f.LogLevelInfo, "info", false, "set log level to 'info'")
	flag.BoolVar(&f.LogLevelWarn, "warning", false, "set log level to 'warning'")
	flag.BoolVar(&f.LogLevelError, "error", false, "set log level to 'error'")
	flag.BoolVar(&f.LogLevelFatal, "fatal", false, "set log level to 'fatal'")

	flag.BoolVar(&f.PrintVersion, "version", false, "display version")
	flag.StringVar(&f.OneShotDSN, "dsn", "", "Process a single data source in time-machine")
	flag.StringVar(&f.Transform, "transform", "", "expr to apply on the event after acquisition")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.Var(&labels, "label", "Additional Labels for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")
	flag.BoolVar(&f.DisableCAPI, "no-capi", false, "disable communication with Central API")
	flag.BoolVar(&f.OrderEvent, "order-event", false, "enforce event ordering with significant performance cost")
	if runtime.GOOS == "windows" {
		flag.StringVar(&f.WinSvc, "winsvc", "", "Windows service Action: Install, Remove etc..")
	}
	flag.StringVar(&dumpFolder, "dump-data", "", "dump parsers/buckets raw outputs")
	flag.Parse()
}

func newLogLevel(curLevelPtr *log.Level, f *Flags) *log.Level {
	// mother of all defaults
	ret := log.InfoLevel

	// keep if already set
	if curLevelPtr != nil {
		ret = *curLevelPtr
	}

	// override from flags
	switch {
	case f.LogLevelTrace:
		ret = log.TraceLevel
	case f.LogLevelDebug:
		ret = log.DebugLevel
	case f.LogLevelInfo:
		ret = log.InfoLevel
	case f.LogLevelWarn:
		ret = log.WarnLevel
	case f.LogLevelError:
		ret = log.ErrorLevel
	case f.LogLevelFatal:
		ret = log.FatalLevel
	default:
	}

	if curLevelPtr != nil && ret == *curLevelPtr {
		// avoid returning a new ptr to the same value
		return curLevelPtr
	}
	return &ret
}

// LoadConfig returns a configuration parsed from configuration file
func LoadConfig(configFile string, disableAgent bool, disableAPI bool, quiet bool) (*csconfig.Config, error) {
	cConfig, _, err := csconfig.NewConfig(configFile, disableAgent, disableAPI, quiet)
	if err != nil {
		return nil, fmt.Errorf("while loading configuration file: %w", err)
	}

	cConfig.Common.LogLevel = newLogLevel(cConfig.Common.LogLevel, flags)

	if dumpFolder != "" {
		parser.ParseDump = true
		parser.DumpFolder = dumpFolder
		leakybucket.BucketPourTrack = true
		dumpStates = true
	}

	if flags.SingleFileType != "" && flags.OneShotDSN != "" {
		// if we're in time-machine mode, we don't want to log to file
		cConfig.Common.LogMedia = "stdout"
	}

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cConfig.Common.LogMedia,
		cConfig.Common.LogDir, *cConfig.Common.LogLevel,
		cConfig.Common.LogMaxSize, cConfig.Common.LogMaxFiles,
		cConfig.Common.LogMaxAge, cConfig.Common.CompressLogs,
		cConfig.Common.ForceColorLogs); err != nil {
		return nil, err
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
		if err := cConfig.LoadAPIServer(); err != nil {
			return nil, err
		}
	}

	if !cConfig.DisableAgent && (cConfig.API == nil || cConfig.API.Client == nil || cConfig.API.Client.Credentials == nil) {
		return nil, errors.New("missing local API credentials for crowdsec agent, abort")
	}

	if cConfig.DisableAPI && cConfig.DisableAgent {
		return nil, errors.New("You must run at least the API Server or crowdsec")
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
		/*if the api is disabled as well, just read file and exit, don't daemonize*/
		if cConfig.DisableAPI {
			cConfig.Common.Daemonize = false
		}
		log.Infof("single file mode : log_media=%s daemonize=%t", cConfig.Common.LogMedia, cConfig.Common.Daemonize)
	}

	if cConfig.Common.PidDir != "" {
		log.Warn("Deprecation warning: the pid_dir config can be safely removed and is not required")
	}

	if cConfig.Common.Daemonize && runtime.GOOS == "windows" {
		log.Debug("Daemonization is not supported on Windows, disabling")
		cConfig.Common.Daemonize = false
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

func main() {
	if err := fflag.RegisterAllFeatures(); err != nil {
		log.Fatalf("failed to register features: %s", err)
	}

	// some features can require configuration or command-line options,
	// so we need to parse them asap. we'll load from feature.yaml later.
	if err := csconfig.LoadFeatureFlagsEnv(log.StandardLogger()); err != nil {
		log.Fatalf("failed to set feature flags from environment: %s", err)
	}

	crowdsecT0 = time.Now()

	log.Debugf("os.Args: %v", os.Args)

	// Handle command line arguments
	flags = &Flags{}
	flags.Parse()

	if len(flag.Args()) > 0 {
		fmt.Fprintf(os.Stderr, "argument provided but not defined: %s\n", flag.Args()[0])
		flag.Usage()
		// the flag package exits with 2 in case of unknown flag
		os.Exit(2)
	}

	if flags.PrintVersion {
		cwversion.Show()
		os.Exit(0)
	}

	err := StartRunSvc()
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(0)
}
