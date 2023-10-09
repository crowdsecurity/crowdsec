package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestLoadDBConfig(t *testing.T) {
	tests := []struct {
		name           string
		Input          *Config
		expectedResult *DatabaseCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				DbConfig: &DatabaseCfg{
					Type:         "sqlite",
					DbPath:       "./testdata/test.db",
					MaxOpenConns: ptr.Of(10),
				},
				Cscli: &CscliCfg{},
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
			},
			expectedResult: &DatabaseCfg{
				Type:             "sqlite",
				DbPath:           "./testdata/test.db",
				MaxOpenConns:     ptr.Of(10),
				DecisionBulkSize: defaultDecisionBulkSize,
			},
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: nil,
			expectedErr:    "no database configuration provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadDBConfig()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expectedResult, tc.Input.DbConfig)
		})
	}
}
