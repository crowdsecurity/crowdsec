package csconfig

import (
	"flag"
	"os"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/outputs"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *CrowdSec
		err            string
	}{
		{
			name: "new configuration: basic",
			expectedResult: &CrowdSec{
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
			},
			err: "",
		},
	}
	for _, test := range tests {
		result := NewCrowdSecConfig()
		isOk := assert.Equal(t, test.expectedResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Infof("test '%s' : OK", test.name)
	}

}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *CrowdSec
		Args           []string
		err            string
	}{
		{
			name: "load configuration: basic",
			expectedResult: &CrowdSec{
				LogLevel:        log.InfoLevel,
				Daemonize:       true,
				Profiling:       true,
				WorkingFolder:   "./tests/",
				DataFolder:      "./tests/",
				ConfigFolder:    "./tests/",
				PIDFolder:       "./tests/",
				LogFolder:       "./tests/",
				LogMode:         "stdout",
				APIMode:         true,
				NbParsers:       1,
				Prometheus:      true,
				HTTPListen:      "127.0.0.1:6060",
				AcquisitionFile: "tests/acquis.yaml",
				CsCliFolder:     "./tests/cscli/",
				SimulationCfg: &SimulationConfig{
					Simulation: false,
					Exclusions: nil,
				},
				SimulationCfgPath: "./tests/simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/config.yaml",
			},
			err: "",
		},
		{
			name: "load configuration: with -file",
			expectedResult: &CrowdSec{
				LogLevel:        log.InfoLevel,
				SingleFile:      "./tests/test.file",
				SingleFileLabel: "test",
				Daemonize:       true,
				Profiling:       true,
				WorkingFolder:   "./tests/",
				DataFolder:      "./tests/",
				ConfigFolder:    "./tests/",
				PIDFolder:       "./tests/",
				LogFolder:       "./tests/",
				LogMode:         "stdout",
				APIMode:         true,
				NbParsers:       1,
				Prometheus:      true,
				HTTPListen:      "127.0.0.1:6060",
				AcquisitionFile: "tests/acquis.yaml",
				CsCliFolder:     "./tests/cscli/",
				SimulationCfg: &SimulationConfig{
					Simulation: false,
					Exclusions: nil,
				},
				SimulationCfgPath: "./tests/simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/config.yaml",
				"-file",
				"./tests/test.file",
				"-type",
				"test",
			},
			err: "",
		},
		{
			name: "load configuration: with -file without -type",
			expectedResult: &CrowdSec{
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
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/config.yaml",
				"-file",
				"./tests/test.file",
			},
			err: "-file requires -type",
		},
		{
			name: "load configuration: all flags set",
			expectedResult: &CrowdSec{
				LogLevel:        log.TraceLevel,
				Daemonize:       true,
				Profiling:       true,
				WorkingFolder:   "./tests/",
				DataFolder:      "./tests/",
				ConfigFolder:    "./tests/",
				PIDFolder:       "./tests/",
				LogFolder:       "./tests/",
				LogMode:         "stdout",
				APIMode:         true,
				Linter:          true,
				NbParsers:       1,
				Prometheus:      true,
				HTTPListen:      "127.0.0.1:6060",
				AcquisitionFile: "./tests/acquis.yaml",
				CsCliFolder:     "./tests/cscli/",
				SimulationCfg: &SimulationConfig{
					Simulation: false,
					Exclusions: nil,
				},
				SimulationCfgPath: "./tests/simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
				RestoreMode: "./tests/states.json",
				DumpBuckets: true,
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/config.yaml",
				"-acquis",
				"./tests/acquis.yaml",
				"-dump-state",
				"-prometheus-metrics",
				"-t",
				"-daemon",
				"-profile",
				"-debug",
				"-trace",
				"-info",
				"-restore-state",
				"./tests/states.json",
				"-api",
			},
			err: "",
		},
		{
			name: "load configuration: bad config file",
			expectedResult: &CrowdSec{
				LogLevel:          log.InfoLevel,
				Daemonize:         true,
				Profiling:         true,
				WorkingFolder:     "./tests/",
				DataFolder:        "./tests/",
				ConfigFolder:      "./tests/",
				PIDFolder:         "./tests/",
				LogFolder:         "./tests/",
				LogMode:           "stdout",
				APIMode:           true,
				Linter:            false,
				NbParsers:         1,
				Prometheus:        true,
				HTTPListen:        "127.0.0.1:6060",
				CsCliFolder:       "./tests/cscli/",
				SimulationCfgPath: "./tests/simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/bad_config.yaml",
			},
			err: "Error while loading configuration : parse './tests/bad_config.yaml' : yaml: unmarshal errors:\n  line 1: field non_existing_field not found in type csconfig.CrowdSec",
		},
		{
			name: "load configuration: bad simulation file",
			expectedResult: &CrowdSec{
				LogLevel:          log.InfoLevel,
				Daemonize:         true,
				Profiling:         true,
				WorkingFolder:     "./tests/",
				DataFolder:        "./tests/",
				ConfigFolder:      "./tests/",
				PIDFolder:         "./tests/",
				LogFolder:         "./tests/",
				LogMode:           "stdout",
				APIMode:           true,
				Linter:            false,
				NbParsers:         1,
				Prometheus:        true,
				AcquisitionFile:   "tests/acquis.yaml",
				HTTPListen:        "127.0.0.1:6060",
				CsCliFolder:       "./tests/cscli/",
				SimulationCfgPath: "./tests/bad_simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/bad_config_simulation.yaml",
			},
			err: `Error while loading configuration : loading simulation config : while parsing './tests/bad_simulation.yaml' : yaml: unmarshal errors:
  line 1: field test not found in type csconfig.SimulationConfig`,
		},
		{
			name: "load configuration: bad config file",
			expectedResult: &CrowdSec{
				LogLevel:          log.InfoLevel,
				Daemonize:         true,
				Profiling:         true,
				WorkingFolder:     "./tests/",
				DataFolder:        "./tests/",
				ConfigFolder:      "./tests/",
				PIDFolder:         "./tests/",
				LogFolder:         "./tests/",
				LogMode:           "stdout",
				APIMode:           true,
				Linter:            false,
				NbParsers:         1,
				Prometheus:        true,
				HTTPListen:        "127.0.0.1:6060",
				CsCliFolder:       "./tests/cscli/",
				SimulationCfgPath: "./tests/simulation.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/bad_config.yaml",
			},
			err: "Error while loading configuration : parse './tests/bad_config.yaml' : yaml: unmarshal errors:\n  line 1: field non_existing_field not found in type csconfig.CrowdSec",
		},
		{
			name: "load configuration: non exist simulation file",
			expectedResult: &CrowdSec{
				LogLevel:          log.InfoLevel,
				Daemonize:         true,
				Profiling:         true,
				WorkingFolder:     "./tests/",
				DataFolder:        "./tests/",
				ConfigFolder:      "./tests/",
				PIDFolder:         "./tests/",
				LogFolder:         "./tests/",
				LogMode:           "stdout",
				APIMode:           true,
				Linter:            false,
				NbParsers:         1,
				Prometheus:        true,
				AcquisitionFile:   "tests/acquis.yaml",
				HTTPListen:        "127.0.0.1:6060",
				CsCliFolder:       "./tests/cscli/",
				SimulationCfgPath: "./tests/non_exist.yaml",
				OutputConfig: &outputs.OutputFactory{
					BackendFolder: "./tests/plugins/backend",
					MaxRecords:    "",
					MaxRecordsAge: "720h",
					Flush:         false,
					Debug:         false,
				},
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/bad_config_simulation_1.yaml",
			},
			err: "Error while loading configuration : loading simulation config : while reading './tests/non_exist.yaml' : open ./tests/non_exist.yaml: no such file or directory",
		},
		{
			name: "load configuration: non existent configuration file",
			expectedResult: &CrowdSec{
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
			},
			Args: []string{
				"crowdsec",
				"-c",
				"./tests/non_exist.yaml",
			},
			err: "Error while loading configuration : read './tests/non_exist.yaml' : open ./tests/non_exist.yaml: no such file or directory",
		},
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	for _, test := range tests {
		log.Printf("testing '%s'", test.name)
		flag.CommandLine = flag.NewFlagSet(test.Args[0], flag.ExitOnError)
		result := NewCrowdSecConfig()
		os.Args = test.Args
		err := result.LoadConfig()

		if test.err != "" {
			if err == nil {
				t.Fatalf("test '%s' should returned an error", test.name)
			}
			isOk := assert.EqualErrorf(t, err, test.err, "")
			if !isOk {
				t.Fatalf("test '%s' failed", test.name)
			}
		}
		if test.err == "" && err != nil {
			t.Fatalf("test '%s' return an error : %s", test.name, err)
		}
		isOk := assert.Equal(t, test.expectedResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Infof("test '%s' : OK", test.name)
	}
}
