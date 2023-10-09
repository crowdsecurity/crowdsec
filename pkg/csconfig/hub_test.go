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
		name           string
		Input          *Config
		expectedResult *Hub
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./testdata",
					DataDir:      "./data",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedResult: &Hub{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name: "no data dir",
			Input: &Config{
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
			Input:       &Config{},
			expectedErr: "no configuration paths provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadHub()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expectedResult, tc.Input.Hub)
		})
	}
}
