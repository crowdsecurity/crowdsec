package main

import (
	"flag"
	"fmt"
	"os"
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

func parseFlags(argv []string) (Flags, error) {
	var f Flags

	fs := flag.NewFlagSet("crowdsec", flag.ExitOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&f.ConfigFile, "c", csconfig.DefaultConfigPath("config.yaml"), "configuration file")

	var trace, debug, info, warn, erro, fatal bool
	fs.BoolVar(&trace, "trace", false, "set log level to 'trace' (VERY verbose)")
	fs.BoolVar(&debug, "debug", false, "set log level to 'debug'")
	fs.BoolVar(&info, "info", false, "set log level to 'info'")
	fs.BoolVar(&warn, "warning", false, "set log level to 'warning'")
	fs.BoolVar(&erro, "error", false, "set log level to 'error'")
	fs.BoolVar(&fatal, "fatal", false, "set log level to 'fatal'")

	fs.BoolVar(&f.PrintVersion, "version", false, "display version")
	fs.StringVar(&f.OneShotDSN, "dsn", "", "Process a single data source in time-machine")
	fs.StringVar(&f.Transform, "transform", "", "expr to apply on the event after acquisition")
	fs.StringVar(&f.SingleFileType, "type", "", "Labels.type for file in time-machine")
	f.Labels = make(labelsMap)
	fs.Var(&f.Labels, "label", "Additional Labels for file in time-machine")
	fs.BoolVar(&f.TestMode, "t", false, "only test configs")
	fs.BoolVar(&f.DisableAgent, "no-cs", false, "disable crowdsec agent")
	fs.BoolVar(&f.DisableAPI, "no-api", false, "disable local API")
	fs.BoolVar(&f.DisableCAPI, "no-capi", false, "disable communication with Central API")
	fs.BoolVar(&f.OrderEvent, "order-event", false, "enforce event ordering with significant performance cost")

	if runtime.GOOS == "windows" {
		fs.StringVar(&f.WinSvc, "winsvc", "", "Windows service Action: Install, Remove etc..")
	}

	fs.StringVar(&f.DumpDir, "dump-data", "", "dump parsers/buckets raw outputs")
	fs.StringVar(&f.CPUProfile, "cpu-profile", "", "write cpu profile to file")

	if err := fs.Parse(argv); err != nil {
		return f, err
	}

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

	if len(fs.Args()) > 0 {
		return f, fmt.Errorf("argument provided but not defined: %s", fs.Args()[0])

	}

	return f, nil
}
