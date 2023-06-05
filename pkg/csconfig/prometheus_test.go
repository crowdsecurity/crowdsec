package csconfig

import (
	"testing"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"

	"github.com/stretchr/testify/require"
)

func TestLoadPrometheus(t *testing.T) {
	tests := []struct {
		name        string
		Input       *Config
		expectedURL string
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
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
			err := tc.Input.LoadPrometheus()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			require.Equal(t, tc.expectedURL, tc.Input.Cscli.PrometheusUrl)
		})
	}
}
