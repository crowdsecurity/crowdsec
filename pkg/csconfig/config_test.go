package csconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
)

func TestNormalLoad(t *testing.T) {
	_, err := NewConfig("./tests/config.yaml", false, false)
	require.NoError(t, err)

	_, err = NewConfig("./tests/xxx.yaml", false, false)
	assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: "+cstest.FileNotFoundMessage)

	_, err = NewConfig("./tests/simulation.yaml", false, false)
	assert.EqualError(t, err, "./tests/simulation.yaml: yaml: unmarshal errors:\n  line 1: field simulation not found in type csconfig.Config")
}

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *Config
	}{
		{
			name:           "new configuration: basic",
			expectedResult: &Config{},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &Config{}
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	x := NewDefaultConfig()
	err := x.Dump()
	require.NoError(t, err)
}
