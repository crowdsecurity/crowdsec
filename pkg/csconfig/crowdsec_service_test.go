package csconfig

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLoadCrowdsec(t *testing.T) {
	falseBoolPtr := false
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
					AcquisitionFilePath: "./tests/acquis.yaml",
					SimulationFilePath:  "./tests/simulation.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
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
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				AcquisitionDirPath:   acquisDirFullPath,
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath, acquisInDirFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
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
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedResult: &CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  "",
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{},
				SimulationFilePath:   "",
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
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
