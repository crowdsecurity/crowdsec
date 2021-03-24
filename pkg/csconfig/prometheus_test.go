package csconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPrometheus(t *testing.T) {

	tests := []struct {
		name           string
		Input          *Config
		expectedResult string
		err            string
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
			expectedResult: "http://127.0.0.1:6060",
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadPrometheus()
		if err == nil && test.err != "" {
			fmt.Printf("TEST '%s': NOK\n", test.name)
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				fmt.Printf("TEST '%s': NOK\n", test.name)
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.Cscli.PrometheusUrl)
		if !isOk {
			t.Fatalf("test '%s' failed\n", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}
	}
}
