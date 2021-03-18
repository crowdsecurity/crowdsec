package csconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimulationLoading(t *testing.T) {
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
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedResult: &SimulationConfig{Simulation: new(bool)},
		},
		{
			name: "basic bad file name",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/xxx.yaml",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: "while reading './tests/xxx.yaml': open ./tests/xxx.yaml: no such file or directory",
		},
		{
			name: "basic nil config",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
		},
		{
			name: "basic bad file content",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/config.yaml",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			err: "while unmarshaling simulation file './tests/config.yaml' : yaml: unmarshal errors",
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadSimulation()
		if err == nil && test.err != "" {
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
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
