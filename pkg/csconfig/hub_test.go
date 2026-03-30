package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadHub(t *testing.T) {
	tests := []struct {
		name        string
		input       *Config
		expected    *LocalHubCfg
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
			expected: &LocalHubCfg{
				HubDir:         "./hub",
				HubIndexFile:   "./hub/.index.json",
				InstallDir:     "./testdata",
				InstallDataDir: "./data",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.input.loadHub()
			assert.Equal(t, tc.expected, tc.input.Hub)
		})
	}
}
