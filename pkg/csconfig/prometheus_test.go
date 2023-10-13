package csconfig

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestLoadPrometheus(t *testing.T) {
	tests := []struct {
		name        string
		input       *Config
		expectedURL string
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				Prometheus: &PrometheusCfg{
					Enabled:    true,
					Level:      "full",
					ListenAddr: "127.0.0.1",
					ListenPort: 6060,
				},
				Cscli: &CscliCfg{},
			},
			expectedURL: "http://127.0.0.1:6060",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadPrometheus()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			require.Equal(t, tc.expectedURL, tc.input.Cscli.PrometheusUrl)
		})
	}
}
