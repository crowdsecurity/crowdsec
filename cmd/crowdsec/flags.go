package main

import (
	"flag"
	"fmt"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type Flags struct {
	ConfigFile string

	LogLevel log.Level

	PrintVersion   bool
	SingleFileType string
	Labels         labelsMap
	OneShotDSN     string
	TestMode       bool
	DisableAgent   bool
	DisableAPI     bool
	WinSvc         string
	DisableCAPI    bool
	Transform      string
	OrderEvent     bool
	CPUProfile     string
	DumpDir        string
}

func (f *Flags) haveTimeMachine() bool {
	return f.OneShotDSN != ""
}

type labelsMap map[string]string

func (*labelsMap) String() string {
	return "labels"
}

func (l *labelsMap) Set(label string) error {
	for pair := range strings.SplitSeq(label, ",") {
		split := strings.Split(pair, ":")
		if len(split) != 2 {
			return fmt.Errorf("invalid format for label '%s', must be key:value", pair)
		}

		(*l)[split[0]] = split[1]
	}

	return nil
}

func (f *Flags) parse() {
	flag.StringVar(&f.ConfigFile, "c", csconfig.DefaultConfigPath("config.yaml"), "configuration file")

	var trace, debug, info, warn, erro, fatal bool

	flag.BoolVar(&trace, "trace", false, "set log level to 'trace' (VERY verbose)")
	flag.BoolVar(&debug, "debug", false, "set log level to 'debug'")
	flag.BoolVar(&info, "info", false, "set log level to 'info'")
	flag.BoolVar(&warn, "warning", false, "set log level to 'warning'")
	flag.BoolVar(&erro, "error", false, "set log level to 'error'")
	flag.BoolVar(&fatal, "fatal", false, "set log level to 'fatal'")

	flag.BoolVar(&f.PrintVersion, "version", false, "display version")
	flag.StringVar(&f.OneShotDSN, "dsn", "", "Process a single data source in time-machine")
	flag.StringVar(&f.Transform, "transform", "", "expr to apply on the event after acquisition")
	flag.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	flag.Var(&f.Labels, "label", "Additional Labels for file in time-machine")
	flag.BoolVar(&f.TestMode, "t", false, "only test configs")
	flag.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	flag.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")
	flag.BoolVar(&f.DisableCAPI, "no-capi", false, "disable communication with Central API")
	flag.BoolVar(&f.OrderEvent, "order-event", false, "enforce event ordering with significant performance cost")

	if runtime.GOOS == "windows" {
		flag.StringVar(&f.WinSvc, "winsvc", "", "Windows service Action: Install, Remove etc..")
	}

	flag.StringVar(&f.DumpDir, "dump-data", "", "dump parsers/buckets raw outputs")
	flag.StringVar(&f.CPUProfile, "cpu-profile", "", "write cpu profile to file")
	flag.Parse()

	// Set the log level selected by the --trace, --debug, --info, etc. flags,
	// giving precedence to the most verbose flag if multiple are set. If no flag is specified,
	// keep the default PanicLevel, which acts as a zero value and should never override another level.
	switch {
	case trace:
		f.LogLevel = log.TraceLevel
	case debug:
		f.LogLevel = log.DebugLevel
	case info:
		f.LogLevel = log.InfoLevel
	case warn:
		f.LogLevel = log.WarnLevel
	case erro:
		f.LogLevel = log.ErrorLevel
	case fatal:
		f.LogLevel = log.FatalLevel
	}
}
