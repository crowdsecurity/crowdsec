package csconfig

import (
	"flag"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"os"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/outputs"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type SimulationConfig struct {
	Simulation bool     `yaml:"simulation"`
	Exclusions []string `yaml:"exclusions,omitempty"`
}

// CrowdSec is the structure of the crowdsec configuration
type CrowdSec struct {
	WorkingFolder     string    `yaml:"working_dir,omitempty"`
	DataFolder        string    `yaml:"data_dir,omitempty"`
	ConfigFolder      string    `yaml:"config_dir,omitempty"`
	AcquisitionFile   string    `yaml:"acquis_path,omitempty"`
	SingleFile        string    //for forensic mode
	SingleFileLabel   string    //for forensic mode
	PIDFolder         string    `yaml:"pid_dir,omitempty"`
	LogFolder         string    `yaml:"log_dir,omitempty"`
	LogMode           string    `yaml:"log_mode,omitempty"`  //like file, syslog or stdout ?
	LogLevel          log.Level `yaml:"log_level,omitempty"` //trace,debug,info,warning,error
	Daemonize         bool      `yaml:"daemon,omitempty"`    //true -> go background
	Profiling         bool      `yaml:"profiling,omitempty"` //true -> enable runtime profiling
	APIMode           bool      `yaml:"apimode,omitempty"`   //true -> enable api push
	CsCliFolder       string    `yaml:"cscli_dir"`           //cscli folder
	NbParsers         int       `yaml:"parser_routines"`     //the number of go routines to start for parsing
	SimulationCfgPath string    `yaml:"simulation_path,omitempty"`
	SimulationCfg     *SimulationConfig
	Linter            bool
	Prometheus        bool
	HTTPListen        string `yaml:"http_listen,omitempty"`
	RestoreMode       string
	DumpBuckets       bool
	OutputConfig      *outputs.OutputFactory `yaml:"plugin"`
}

// NewCrowdSecConfig create a new crowdsec configuration with default configuration
func NewCrowdSecConfig() *CrowdSec {
	return &CrowdSec{
		LogLevel:      log.InfoLevel,
		Daemonize:     false,
		Profiling:     false,
		WorkingFolder: "/tmp/",
		DataFolder:    "/var/lib/crowdsec/data/",
		ConfigFolder:  "/etc/crowdsec/config/",
		PIDFolder:     "/var/run/",
		LogFolder:     "/var/log/",
		LogMode:       "stdout",
		APIMode:       false,
		NbParsers:     1,
		Prometheus:    false,
		HTTPListen:    "127.0.0.1:6060",
	}
}

func (c *CrowdSec) LoadSimulation() error {
	if c.SimulationCfgPath != "" {
		rcfg, err := ioutil.ReadFile(c.SimulationCfgPath)
		if err != nil {
			return fmt.Errorf("while reading '%s' : %s", c.SimulationCfgPath, err)
		}
		simCfg := SimulationConfig{}
		if err := yaml.UnmarshalStrict(rcfg, &simCfg); err != nil {
			return fmt.Errorf("while parsing '%s' : %s", c.SimulationCfgPath, err)
		}
		c.SimulationCfg = &simCfg
	}
	return nil
}

func (c *CrowdSec) LoadConfigurationFile(configFile *string) error {
	/*overriden by cfg file*/
	if *configFile != "" {
		rcfg, err := ioutil.ReadFile(*configFile)
		if err != nil {
			return fmt.Errorf("read '%s' : %s", *configFile, err)
		}
		if err := yaml.UnmarshalStrict(rcfg, c); err != nil {
			return fmt.Errorf("parse '%s' : %s", *configFile, err)
		}
		if c.AcquisitionFile == "" {
			c.AcquisitionFile = filepath.Clean(c.ConfigFolder + "/acquis.yaml")
		}
	}
	if err := c.LoadSimulation(); err != nil {
		return fmt.Errorf("loading simulation config : %s", err)
	}
	return nil
}

// GetOPT return flags parsed from command line
func (c *CrowdSec) LoadConfig() error {
	AcquisitionFile := flag.String("acquis", "", "path to acquis.yaml")
	configFile := flag.String("c", "", "configuration file")
	printTrace := flag.Bool("trace", false, "VERY verbose")
	printDebug := flag.Bool("debug", false, "print debug-level on stdout")
	printInfo := flag.Bool("info", false, "print info-level on stdout")
	printVersion := flag.Bool("version", false, "display version")
	APIMode := flag.Bool("api", false, "perform pushes to api")
	profileMode := flag.Bool("profile", false, "Enable performance profiling")
	catFile := flag.String("file", "", "Process a single file in time-machine")
	catFileType := flag.String("type", "", "Labels.type for file in time-machine")
	daemonMode := flag.Bool("daemon", false, "Daemonize, go background, drop PID file, log to file")
	testMode := flag.Bool("t", false, "only test configs")
	prometheus := flag.Bool("prometheus-metrics", false, "expose http prometheus collector (see http_listen)")
	restoreMode := flag.String("restore-state", "", "[dev] restore buckets state from json file")
	dumpMode := flag.Bool("dump-state", false, "[dev] Dump bucket state at the end of run.")

	flag.Parse()

	if *printVersion {
		cwversion.Show()
		os.Exit(0)
	}

	if *catFile != "" {
		if *catFileType == "" {
			return fmt.Errorf("-file requires -type")
		}
		c.SingleFile = *catFile
		c.SingleFileLabel = *catFileType
	}

	if err := c.LoadConfigurationFile(configFile); err != nil {
		return fmt.Errorf("Error while loading configuration : %s", err)
	}

	if *AcquisitionFile != "" {
		c.AcquisitionFile = *AcquisitionFile
	}
	if *dumpMode {
		c.DumpBuckets = true
	}
	if *prometheus {
		c.Prometheus = true
	}
	if *testMode {
		c.Linter = true
	}
	/*overriden by cmdline*/
	if *daemonMode {
		c.Daemonize = true
	}
	if *profileMode {
		c.Profiling = true
	}
	if *printDebug {
		c.LogLevel = log.DebugLevel
	}
	if *printInfo {
		c.LogLevel = log.InfoLevel
	}
	if *printTrace {
		c.LogLevel = log.TraceLevel
	}
	if *APIMode {
		c.APIMode = true
	}

	if *restoreMode != "" {
		c.RestoreMode = *restoreMode
	}

	return nil
}
