package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestLoadCSCLI(t *testing.T) {
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
				PrometheusUrl: "http://127.0.0.1:6060/metrics",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.loadCSCLI()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Cscli)
		})
	}
}
