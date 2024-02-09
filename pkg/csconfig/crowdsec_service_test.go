package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestLoadCrowdsec(t *testing.T) {
	acquisFullPath, err := filepath.Abs("./testdata/acquis.yaml")
	require.NoError(t, err)

	acquisInDirFullPath, err := filepath.Abs("./testdata/acquis/acquis.yaml")
	require.NoError(t, err)

	acquisDirFullPath, err := filepath.Abs("./testdata/acquis")
	require.NoError(t, err)

	contextFileFullPath, err := filepath.Abs("./testdata/context.yaml")
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *Config
		expected    *CrowdsecServiceCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./testdata",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./testdata/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath:       "./testdata/acquis.yaml",
					SimulationFilePath:        "./testdata/simulation.yaml",
					ConsoleContextPath:        "./testdata/context.yaml",
					ConsoleContextValueLength: 2500,
				},
			},
			expected: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        "",
				ConsoleContextPath:        contextFileFullPath,
				AcquisitionFilePath:       acquisFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 2500,
				AcquisitionFiles:          []string{acquisFullPath},
				SimulationFilePath:        "./testdata/simulation.yaml",
				// context is loaded in pkg/alertcontext
//				ContextToSend: map[string][]string{
//					"source_ip": {"evt.Parsed.source_ip"},
//				},
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "basic valid configuration with acquisition dir",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./testdata",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./testdata/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "./testdata/acquis.yaml",
					AcquisitionDirPath:  "./testdata/acquis/",
					SimulationFilePath:  "./testdata/simulation.yaml",
					ConsoleContextPath:  "./testdata/context.yaml",
				},
			},
			expected: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        acquisDirFullPath,
				AcquisitionFilePath:       acquisFullPath,
				ConsoleContextPath:        contextFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 0,
				AcquisitionFiles:          []string{acquisFullPath, acquisInDirFullPath},
				// context is loaded in pkg/alertcontext
//				ContextToSend: map[string][]string{
//					"source_ip": {"evt.Parsed.source_ip"},
//				},
				SimulationFilePath: "./testdata/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "no acquisition file and dir",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./testdata",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./testdata/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					ConsoleContextPath:        "./testdata/context.yaml",
					ConsoleContextValueLength: 10,
				},
			},
			expected: &CrowdsecServiceCfg{
				Enable:                    ptr.Of(true),
				AcquisitionDirPath:        "",
				AcquisitionFilePath:       "",
				ConsoleContextPath:        contextFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				ConsoleContextValueLength: 10,
				AcquisitionFiles:          []string{},
				SimulationFilePath:        "",
				// context is loaded in pkg/alertcontext
//				ContextToSend: map[string][]string{
//					"source_ip": {"evt.Parsed.source_ip"},
//				},
				SimulationConfig: &SimulationConfig{
					Simulation: ptr.Of(false),
				},
			},
		},
		{
			name: "non existing acquisition file",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./testdata",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./testdata/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					ConsoleContextPath:  "",
					AcquisitionFilePath: "./testdata/acquis_not_exist.yaml",
				},
			},
			expectedErr: cstest.FileNotFoundMessage,
		},
		{
			name: "agent disabled",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./testdata",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
			},
			expected: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadCrowdsec()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expected, tc.input.Crowdsec)
		})
	}
}
