package csconfig

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/crowdsecurity/go-cs-lib/cstest"
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

	notExist := "./testdata/acquis_not_exist.yaml"

	notExistFullPath, err := filepath.Abs(notExist)
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
				Enable:                    new(true),
				AcquisitionDirPath:        "",
				ConsoleContextPath:        contextFileFullPath,
				AcquisitionFilePath:       acquisFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				PostOverflowQueueSize:     defaultPostOverflowQueueSize,
				ConsoleContextValueLength: 2500,
				AcquisitionFiles:          []string{acquisFullPath},
				SimulationFilePath:        "./testdata/simulation.yaml",
				// context is loaded in pkg/alertcontext
				// ContextToSend: map[string][]string{
				// 	"source_ip": {"evt.Parsed.source_ip"},
				// },
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
				Enable:                    new(true),
				AcquisitionDirPath:        acquisDirFullPath,
				AcquisitionFilePath:       acquisFullPath,
				ConsoleContextPath:        contextFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				PostOverflowQueueSize:     defaultPostOverflowQueueSize,
				ConsoleContextValueLength: 0,
				AcquisitionFiles:          []string{acquisFullPath, acquisInDirFullPath},
				// context is loaded in pkg/alertcontext
				// ContextToSend: map[string][]string{
				// 	"source_ip": {"evt.Parsed.source_ip"},
				// },
				SimulationFilePath: "./testdata/simulation.yaml",
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
				Enable:                    new(true),
				AcquisitionDirPath:        "",
				AcquisitionFilePath:       "",
				ConsoleContextPath:        contextFileFullPath,
				BucketsRoutinesCount:      1,
				ParserRoutinesCount:       1,
				OutputRoutinesCount:       1,
				PostOverflowQueueSize:     defaultPostOverflowQueueSize,
				ConsoleContextValueLength: 10,
				AcquisitionFiles:          []string{},
				SimulationFilePath:        "",
				// context is loaded in pkg/alertcontext
				// ContextToSend: map[string][]string{
				// 	"source_ip": {"evt.Parsed.source_ip"},
				// },
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
					AcquisitionFilePath: notExist,
				},
			},
			expected: &CrowdsecServiceCfg{
				Enable:                new(true),
				AcquisitionFilePath:   notExistFullPath,
				AcquisitionFiles:      []string{},
				ParserRoutinesCount:   1,
				OutputRoutinesCount:   1,
				PostOverflowQueueSize: defaultPostOverflowQueueSize,
				BucketsRoutinesCount:  1,
			},
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

func TestDNSCacheCfg(t *testing.T) {
	yamlConfig := `
acquisition_path: ./testdata/acquis.yaml
dns_cache:
  ttl: 2h
  negative_ttl: 30s
  size: 4096
`

	cfg := CrowdsecServiceCfg{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlConfig), &cfg))

	require.NotNil(t, cfg.DNSCache)
	require.NotNil(t, cfg.DNSCache.TTL)
	assert.Equal(t, 2*time.Hour, *cfg.DNSCache.TTL)
	require.NotNil(t, cfg.DNSCache.NegativeTTL)
	assert.Equal(t, 30*time.Second, *cfg.DNSCache.NegativeTTL)
	require.NotNil(t, cfg.DNSCache.Size)
	assert.Equal(t, 4096, *cfg.DNSCache.Size)

	// the section is optional
	bare := CrowdsecServiceCfg{}
	require.NoError(t, yaml.Unmarshal([]byte("acquisition_path: ./testdata/acquis.yaml"), &bare))
	assert.Nil(t, bare.DNSCache)
}

func TestPipelineCfg(t *testing.T) {
	tests := []struct {
		name            string
		yamlConfig      string
		expectedParser  int
		expectedBuckets int
		expectedOutput  int
		expectedQueue   int
	}{
		{
			name:            "nothing set",
			yamlConfig:      "",
			expectedParser:  1,
			expectedBuckets: 1,
			expectedOutput:  1,
			expectedQueue:   256,
		},
		{
			name: "legacy keys only",
			yamlConfig: `
parser_routines: 4
buckets_routines: 2
output_routines: 3
`,
			expectedParser:  4,
			expectedBuckets: 2,
			expectedOutput:  3,
			expectedQueue:   256,
		},
		{
			name: "nested keys only",
			yamlConfig: `
pipeline:
  parser:
    routines: 4
  buckets:
    routines: 2
  output:
    routines: 3
    queue_size: 512
`,
			expectedParser:  4,
			expectedBuckets: 2,
			expectedOutput:  3,
			expectedQueue:   512,
		},
		{
			// config.yaml ships parser_routines, so this is what an upgrade looks like
			name: "nested overrides legacy",
			yamlConfig: `
parser_routines: 1
pipeline:
  parser:
    routines: 8
`,
			expectedParser:  8,
			expectedBuckets: 1,
			expectedOutput:  1,
			expectedQueue:   256,
		},
		{
			name:            "a negative legacy value falls back to the default",
			yamlConfig:      "parser_routines: -1",
			expectedParser:  1,
			expectedBuckets: 1,
			expectedOutput:  1,
			expectedQueue:   256,
		},
		{
			name: "zero and negative values fall back to the defaults",
			yamlConfig: `
pipeline:
  parser:
    routines: 0
  output:
    routines: -1
    queue_size: 0
`,
			expectedParser:  1,
			expectedBuckets: 1,
			expectedOutput:  1,
			expectedQueue:   256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crowdsecCfg := CrowdsecServiceCfg{}
			require.NoError(t, yaml.Unmarshal([]byte(tc.yamlConfig), &crowdsecCfg))

			crowdsecCfg.AcquisitionFilePath = "./testdata/acquis.yaml"
			crowdsecCfg.SimulationFilePath = "./testdata/simulation.yaml"

			cfg := &Config{
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
				Crowdsec: &crowdsecCfg,
			}

			require.NoError(t, cfg.LoadCrowdsec())

			require.Equal(t, tc.expectedParser, cfg.Crowdsec.ParserRoutinesCount)
			require.Equal(t, tc.expectedBuckets, cfg.Crowdsec.BucketsRoutinesCount)
			require.Equal(t, tc.expectedOutput, cfg.Crowdsec.OutputRoutinesCount)
			require.Equal(t, tc.expectedQueue, cfg.Crowdsec.PostOverflowQueueSize)
		})
	}
}
