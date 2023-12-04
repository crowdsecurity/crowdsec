package csconfig

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestSimulationLoading(t *testing.T) {
	tests := []struct {
		name        string
		input       *Config
		expected    *SimulationConfig
		expectedErr string
	}{
		{
			name: "basic valid simulation",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./testdata/simulation.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
				Cscli:    &CscliCfg{},
			},
			expected: &SimulationConfig{Simulation: new(bool)},
		},
		{
			name: "basic nil config",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: "simulation.yaml: " + cstest.FileNotFoundMessage,
		},
		{
			name: "basic bad file name",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./testdata/xxx.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: fmt.Sprintf("while reading yaml file: open ./testdata/xxx.yaml: %s", cstest.FileNotFoundMessage),
		},
		{
			name: "basic bad file content",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./testdata/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: "while unmarshaling simulation file './testdata/config.yaml' : yaml: unmarshal errors",
		},
		{
			name: "basic bad file content",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./testdata/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: "while unmarshaling simulation file './testdata/config.yaml' : yaml: unmarshal errors",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadSimulation()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			assert.Equal(t, tc.expected, tc.input.Crowdsec.SimulationConfig)
		})
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
		expected         bool
	}{
		{
			name:             "No simulation except (in exclusion)",
			SimulationConfig: simCfgOff,
			Input:            "test",
			expected:         true,
		},
		{
			name:             "All simulation (not in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "toto",
			expected:         true,
		},
		{
			name:             "All simulation (in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "test",
			expected:         false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			isSimulated := tc.SimulationConfig.IsSimulated(tc.Input)
			require.Equal(t, tc.expected, isSimulated)
		})
	}
}
