package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCSCLI(t *testing.T) {
	tests := []struct {
		name     string
		input    *Config
		expected *CscliCfg
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
				PrometheusUrl:  "http://127.0.0.1:6060/metrics",
				HubURLTemplate: defaultHubURLTemplate,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.input.loadCSCLI()
			assert.Equal(t, tc.expected, tc.input.Cscli)
		})
	}
}
