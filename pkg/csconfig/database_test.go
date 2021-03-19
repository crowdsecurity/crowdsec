package csconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadDBConfig(t *testing.T) {
	tests := []struct {
		name           string
		Input          *Config
		expectedResult *DatabaseCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				DbConfig: &DatabaseCfg{
					Type:   "sqlite",
					DbPath: "./tests/test.db",
				},
				Cscli: &CscliCfg{},
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
			},
			expectedResult: &DatabaseCfg{
				Type:   "sqlite",
				DbPath: "./tests/test.db",
			},
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: nil,
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadDBConfig()
		if err == nil && test.err != "" {
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.DbConfig)
		if !isOk {
			fmt.Printf("TEST: '%v' failed", test.name)
			t.Fatal()
		}
	}
}
