package csconfig

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	x := NewDefaultConfig()
	x.Dump()
}

func TestNormalLoad(t *testing.T) {

	x := NewConfig()
	err := x.LoadConfigurationFile("./tests/config.yaml")
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	x = NewConfig()
	err = x.LoadConfigurationFile("./tests/xxx.yaml")
	if fmt.Sprintf("%s", err) != "failed to read config file: open ./tests/xxx.yaml: no such file or directory" {
		t.Fatalf("unexpected error %s", err)
	}

	x = NewConfig()
	err = x.LoadConfigurationFile("./tests/simulation.yaml")
	if !strings.HasPrefix(fmt.Sprintf("%s", err), "failed unmarshaling config: yaml: unmarshal error") {
		t.Fatalf("unexpected error %s", err)
	}

}

func TestCleanupPaths(t *testing.T) {
	tests := []struct {
		name           string
		Input          *GlobalConfig
		expectedResult *GlobalConfig
		err            string
	}{
		{
			name: "daemon cleanup",
			Input: &GlobalConfig{
				Daemon: &DaemonCfg{
					PidDir:     "////tmp//",
					LogDir:     "/////tmp///",
					WorkingDir: "/////tmp///",
				},
			},
			expectedResult: &GlobalConfig{
				Daemon: &DaemonCfg{
					PidDir:     "/tmp",
					LogDir:     "/tmp",
					WorkingDir: "/tmp",
				},
			},
		},
		//
		{
			name: "crowdsec cleanup",
			Input: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "////tmp//x.yaml",
					SimulationFilePath:  "////tmp//x.yaml",
					ConfigDir:           "////tmp//",
					DataDir:             "////tmp//",
				},
			},
			expectedResult: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "/tmp/x.yaml",
					SimulationFilePath:  "/tmp/x.yaml",
					ConfigDir:           "/tmp",
					DataDir:             "/tmp",
				},
			},
		},
		//
		{
			name: "cscli cleanup",
			Input: &GlobalConfig{
				Cscli: &CscliCfg{
					HubDir:     "////tmp//",
					IndexPath:  "////tmp//x.yaml",
					InstallDir: "////tmp//",
					DataDir:    "////tmp//",
				},
			},
			expectedResult: &GlobalConfig{
				Cscli: &CscliCfg{
					HubDir:     "/tmp",
					IndexPath:  "/tmp/x.yaml",
					InstallDir: "/tmp",
					DataDir:    "/tmp",
				},
			},
		},
	}
	for idx, test := range tests {
		err := test.Input.CleanupPaths()
		if test.err != "" {
			if strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected err %s got %s", idx, len(tests), test.err, fmt.Sprintf("%s", err))
			}
		}
		isOk := assert.Equal(t, test.expectedResult, test.Input)
		if !isOk {
			t.Fatalf("%d/%d failed test", idx, len(tests))
		}
	}
}

func TestSimulationLoading(t *testing.T) {
	tests := []struct {
		name           string
		Input          *GlobalConfig
		expectedResult *SimulationConfig
		err            string
	}{
		{
			name: "basic valid simulation",
			Input: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					SimulationFilePath: "./tests/simulation.yaml",
				},
			},
			expectedResult: &SimulationConfig{},
		},
		{
			name: "basic bad file name",
			Input: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					SimulationFilePath: "./tests/xxx.yaml",
				},
			},
			err: "while reading './tests/xxx.yaml' : open ./tests/xxx.yaml: no such file or directory",
		},
		{
			name: "basic nil config",
			Input: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					SimulationFilePath: "",
				},
			},
		},
		{
			name: "basic bad file content",
			Input: &GlobalConfig{
				Crowdsec: &CrowdsecServiceCfg{
					SimulationFilePath: "./tests/config.yaml",
				},
			},
			err: "while parsing './tests/config.yaml' : yaml: unmarshal",
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadSimulation()
		if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.Crowdsec.SimulationConfig)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}

	}

}

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *GlobalConfig
		err            string
	}{
		{
			name:           "new configuration: basic",
			expectedResult: &GlobalConfig{},
			err:            "",
		},
	}
	for _, test := range tests {
		result := NewConfig()
		isOk := assert.Equal(t, test.expectedResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Infof("test '%s' : OK", test.name)
	}

}
