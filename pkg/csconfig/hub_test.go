package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestLoadHub(t *testing.T) {
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
		expected    *HubCfg
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
			},
			expected: &HubCfg{
				HubDir:         hubFullPath,
				HubIndexFile:   hubIndexFileFullPath,
				InstallDir:     configDirFullPath,
				InstallDataDir: dataFullPath,
			},
		},
		{
			name: "no data dir",
			input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./testdata",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedErr: "please provide a data directory with the 'data_dir' directive in the 'config_paths' section",
		},
		{
			name:        "no configuration path",
			input:       &Config{},
			expectedErr: "no configuration paths provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadHub()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Hub)
		})
	}
}
