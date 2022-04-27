package csconfig

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimulationLoading(t *testing.T) {

	testXXFullPath, err := filepath.Abs("./tests/xxx.yaml")
	if err != nil {
		panic(err)
	}

	badYamlFullPath, err := filepath.Abs("./tests/config.yaml")
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *SimulationConfig
		err            string
	}{
		{
			name: "basic valid simulation",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/simulation.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
				Cscli:    &CscliCfg{},
			},
			expectedResult: &SimulationConfig{Simulation: new(bool)},
		},
		{
			name: "basic nil config",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: fmt.Sprintf("while reading %s: open %s: no such file or directory", testXXFullPath, testXXFullPath),
		},
		{
			name: "basic bad file content",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: fmt.Sprintf("while unmarshaling simulation file '%s' : yaml: unmarshal errors", badYamlFullPath),
		},
		{
			name: "basic bad file content",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: fmt.Sprintf("while unmarshaling simulation file '%s' : yaml: unmarshal errors", badYamlFullPath),
		},
	}

	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name           string
			Input          *Config
			expectedResult *SimulationConfig
			err            string
		}{
			name: "basic bad file name",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/xxx.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: fmt.Sprintf("while reading '%s': open %s: The system cannot find the file specified.", testXXFullPath, testXXFullPath),
		})
	} else {
		tests = append(tests, struct {
			name           string
			Input          *Config
			expectedResult *SimulationConfig
			err            string
		}{
			name: "basic bad file name",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/xxx.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: fmt.Sprintf("while reading '%s': open %s: no such file or directory", testXXFullPath, testXXFullPath),
		})
	}

	for idx, test := range tests {
		err := test.Input.LoadSimulation()
		if err == nil && test.err != "" {
			fmt.Printf("TEST '%s': NOK\n", test.name)
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		}
		if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				fmt.Printf("TEST '%s': NOK\n", test.name)
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}
		isOk := assert.Equal(t, test.expectedResult, test.Input.Crowdsec.SimulationConfig)
		if !isOk {
			t.Fatalf("TEST '%s': NOK\n", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}
	}
}

func TestIsSimulated(t *testing.T) {
	simCfgOff := &SimulationConfig{
		Simulation: new(bool),
		Exclusions: []string{"test"},
	}

	simCfgOn := &SimulationConfig{
		Simulation: new(bool),
		Exclusions: []string{"test"},
	}
	*simCfgOn.Simulation = true

	tests := []struct {
		name             string
		SimulationConfig *SimulationConfig
		Input            string
		expectedResult   bool
		err              string
	}{
		{
			name:             "No simulation except (in exclusion)",
			SimulationConfig: simCfgOff,
			Input:            "test",
			expectedResult:   true,
		},
		{
			name:             "All simulation (not in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "toto",
			expectedResult:   true,
		},
		{
			name:             "All simulation (in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "test",
			expectedResult:   false,
		},
	}
	for _, test := range tests {
		IsSimulated := test.SimulationConfig.IsSimulated(test.Input)
		isOk := assert.Equal(t, test.expectedResult, IsSimulated)
		if !isOk {
			fmt.Printf("TEST: '%v' failed", test.name)
			t.Fatal()
		}
	}

}
