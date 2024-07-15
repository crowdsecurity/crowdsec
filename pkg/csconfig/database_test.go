package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestLoadDBConfig(t *testing.T) {
	tests := []struct {
		name        string
		input       *Config
		expected    *DatabaseCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				DbConfig: &DatabaseCfg{
					Type:         "sqlite",
					DbPath:       "./testdata/test.db",
					MaxOpenConns: 10,
				},
				Cscli: &CscliCfg{},
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
			},
			expected: &DatabaseCfg{
				Type:             "sqlite",
				DbPath:           "./testdata/test.db",
				MaxOpenConns:     10,
				UseWal:           ptr.Of(true),
				DecisionBulkSize: defaultDecisionBulkSize,
			},
		},
		{
			name:        "no configuration path",
			input:       &Config{},
			expected:    nil,
			expectedErr: "no database configuration provided",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadDBConfig(false)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.DbConfig)
		})
	}
}
