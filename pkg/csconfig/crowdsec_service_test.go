package csconfig

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"
	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"

	"github.com/stretchr/testify/require"
)

func TestLoadCrowdsec(t *testing.T) {
	acquisFullPath, err := filepath.Abs("./tests/acquis.yaml")
	require.NoError(t, err)

	acquisInDirFullPath, err := filepath.Abs("./tests/acquis/acquis.yaml")
	require.NoError(t, err)

	acquisDirFullPath, err := filepath.Abs("./tests/acquis")
	require.NoError(t, err)

	hubFullPath, err := filepath.Abs("./hub")
	require.NoError(t, err)

	dataFullPath, err := filepath.Abs("./data")
	require.NoError(t, err)

	configDirFullPath, err := filepath.Abs("./tests")
	require.NoError(t, err)

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
	require.NoError(t, err)

	contextFileFullPath, err := filepath.Abs("./tests/context.yaml")
	require.NoError(t, err)

	tests := []struct {
		name           string
		input          *Config
		expectedResult *CrowdsecServiceCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath:       "./tests/acquis.yaml",
					SimulationFilePath:        "./tests/simulation.yaml",
					ConsoleContextPath:        "./tests/context.yaml",
					ConsoleContextValueLength: 2500,
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        "",
				ConsoleContextPath:        contextFileFullPath,
				AcquisitionFilePath:       acquisFullPath,
				ConfigDir:                 configDirFullPath,
				DataDir:                   dataFullPath,
				HubDir:                    hubFullPath,
				HubIndexFile:              hubIndexFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 2500,
				AcquisitionFiles:          []string{acquisFullPath},
				SimulationFilePath:        "./tests/simulation.yaml",
				ContextToSend: map[string][]string{
					"source_ip": {"evt.Parsed.source_ip"},
				},
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "basic valid configuration with acquisition dir",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis.yaml",
					AcquisitionDirPath:  "./tests/acquis/",
					SimulationFilePath:  "./tests/simulation.yaml",
					ConsoleContextPath:  "./tests/context.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        acquisDirFullPath,
				AcquisitionFilePath:       acquisFullPath,
				ConsoleContextPath:        contextFileFullPath,
				ConfigDir:                 configDirFullPath,
				HubIndexFile:              hubIndexFileFullPath,
				DataDir:                   dataFullPath,
				HubDir:                    hubFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 0,
				AcquisitionFiles:          []string{acquisFullPath, acquisInDirFullPath},
				ContextToSend: map[string][]string{
					"source_ip": {"evt.Parsed.source_ip"},
				},
				SimulationFilePath: "./tests/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "no acquisition file and dir",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					ConsoleContextPath:        contextFileFullPath,
					ConsoleContextValueLength: 10,
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        "",
				AcquisitionFilePath:       "",
				ConfigDir:                 configDirFullPath,
				HubIndexFile:              hubIndexFileFullPath,
				DataDir:                   dataFullPath,
				HubDir:                    hubFullPath,
				ConsoleContextPath:        contextFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 10,
				AcquisitionFiles:          []string{},
				SimulationFilePath:        "",
				ContextToSend: map[string][]string{
					"source_ip": {"evt.Parsed.source_ip"},
				},
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "non existing acquisition file",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					ConsoleContextPath:  "",
					AcquisitionFilePath: "./tests/acquis_not_exist.yaml",
				},
			},
			expectedErr: cstest.FileNotFoundMessage,
		},
		{
			name: "agent disabled",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
			},
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("TEST '%s'\n", tc.name)
			err := tc.input.LoadCrowdsec()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.input.Crowdsec)
		})
	}
}
