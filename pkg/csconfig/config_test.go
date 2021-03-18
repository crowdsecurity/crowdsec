package csconfig

import (
	"fmt"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	x := NewDefaultConfig()
	x.Dump()
}

func TestNormalLoad(t *testing.T) {

	_, err := NewConfig("./tests/config.yaml", false, false)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	_, err = NewConfig("./tests/xxx.yaml", false, false)
	if fmt.Sprintf("%s", err) != "failed to read config file: open ./tests/xxx.yaml: no such file or directory" {
		t.Fatalf("unexpected error %s", err)
	}

	_, err = NewConfig("./tests/simulation.yaml", false, false)
	if !strings.HasPrefix(fmt.Sprintf("%s", err), "yaml: unmarshal errors:") {
		t.Fatalf("unexpected error %s", err)
	}

}

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *Config
		err            string
	}{
		{
			name:           "new configuration: basic",
			expectedResult: &Config{},
			err:            "",
		},
	}
	for _, test := range tests {
		result := &Config{}
		isOk := assert.Equal(t, test.expectedResult, result)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}
		log.Infof("test '%s' : OK", test.name)
	}

}
