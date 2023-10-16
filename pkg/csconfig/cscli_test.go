package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestLoadCSCLI(t *testing.T) {
	hubFullPath, err := filepath.Abs("./hub")
	require.NoError(t, err)

	dataFullPath, err := filepath.Abs("./data")
	require.NoError(t, err)

	configDirFullPath, err := filepath.Abs("./testdata")
	require.NoError(t, err)

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *Config
		expected    *CscliCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./testdata",
					DataDir:      "./data",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
				Prometheus: &PrometheusCfg{
					Enabled:    true,
					Level:      "full",
					ListenAddr: "127.0.0.1",
					ListenPort: 6060,
				},
			},
			expected: &CscliCfg{
				ConfigDir:     configDirFullPath,
				DataDir:       dataFullPath,
				HubDir:        hubFullPath,
				HubIndexFile:  hubIndexFileFullPath,
				PrometheusUrl: "http://127.0.0.1:6060/metrics",
			},
		},
		{
			name:        "no configuration path",
			input:       &Config{},
			expected:    &CscliCfg{},
			expectedErr: "no configuration paths provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadCSCLI()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Cscli)
		})
	}
}
