package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	_ "net/http/pprof"
	"time"

	"sort"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"

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

	flags *Flags

	/*the state of acquisition*/
	dataSources []acquisition.DataSource
	/*the state of the buckets*/
	holders         []leaky.BucketFactory
	buckets         *leaky.Buckets
	outputEventChan chan types.Event //the buckets init returns its own chan that is used for multiplexing
	/*settings*/
	lastProcessedItem time.Time /*keep track of last item timestamp in time-machine. it is used to GC buckets when we dump them.*/
)

type Flags struct {
	ConfigFile             string
	TraceLevel             bool
	DebugLevel             bool
	InfoLevel              bool
	PrintVersion           bool
	SingleFilePath         string
	SingleJournalctlFilter string
	SingleFileType         string
	SingleFileJsonOutput   string
	TestMode               bool
	DisableAgent           bool
	DisableAPI             bool
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

	if flags.SingleFilePath != "" || flags.SingleJournalctlFilter != "" {

		tmpCfg := acquisition.DataSourceCfg{}
		tmpCfg.Mode = acquisition.CAT_MODE
		tmpCfg.Labels = map[string]string{"type": flags.SingleFileType}

		if flags.SingleFilePath != "" {
			tmpCfg.Filename = flags.SingleFilePath
		} else if flags.SingleJournalctlFilter != "" {
			tmpCfg.JournalctlFilters = strings.Split(flags.SingleJournalctlFilter, " ")
		}

		datasrc, err := acquisition.DataSourceConfigure(tmpCfg)
		if err != nil {
			return fmt.Errorf("while configuring specified file datasource : %s", err)
		}
		if dataSources == nil {
			dataSources = make([]acquisition.DataSource, 0)
		}
		dataSources = append(dataSources, datasrc)
	} else {
		dataSources, err = acquisition.LoadAcquisitionFromFile(cConfig.Crowdsec)
		if err != nil {
			log.Fatalf("While loading acquisition configuration : %s", err)
		}
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
	flag.StringVar(&f.SingleJournalctlFilter, "jfilter", "", "Process a single journalctl output in time-machine")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")

	flag.Parse()
}

// LoadConfig return configuration parsed from configuration file
func LoadConfig(cConfig *csconfig.Config) error {

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

	if flags.SingleFilePath != "" {
		if flags.SingleFileType == "" {
			return fmt.Errorf("-file requires -type")
		}
	}

	if flags.SingleJournalctlFilter != "" {
		if flags.SingleFileType == "" {
			return fmt.Errorf("-jfilter requires -type")
		}
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

	if flags.SingleFilePath != "" || flags.SingleJournalctlFilter != "" {
		cConfig.API.Server.OnlineClient = nil
		/*if the api is disabled as well, just read file and exit, don't daemonize*/
		if flags.DisableAPI {
			cConfig.Common.Daemonize = false
		}
		cConfig.Common.LogMedia = "stdout"
		log.Infof("single file mode : log_media=%s daemonize=%t", cConfig.Common.LogMedia, cConfig.Common.Daemonize)
	}

	return nil
}

func main() {
	var (
		cConfig *csconfig.Config
		err     error
	)

	defer types.CatchPanic("crowdsec/main")

	// Handle command line arguments
	flags = &Flags{}
	flags.Parse()
	if flags.PrintVersion {
		cwversion.Show()
		os.Exit(0)
	}

	cConfig, err = csconfig.NewConfig(flags.ConfigFile, flags.DisableAgent, flags.DisableAPI)
	if err != nil {
		log.Fatalf(err.Error())
	}
	if err := LoadConfig(cConfig); err != nil {
		log.Fatalf(err.Error())
	}
	// Configure logging
	if err = types.SetDefaultLoggerConfig(cConfig.Common.LogMedia, cConfig.Common.LogDir, *cConfig.Common.LogLevel); err != nil {
		log.Fatal(err.Error())
	}

	log.Infof("Crowdsec %s", cwversion.VersionStr())

	// Enable profiling early
	if cConfig.Prometheus != nil {
		go registerPrometheus(cConfig.Prometheus)
	}

	if err := Serve(cConfig); err != nil {
		log.Fatalf(err.Error())
	}

}
