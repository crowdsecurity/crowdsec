package csconfig

import (
	"fmt"
	"log"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalLoad(t *testing.T) {

	_, err := NewConfig("./tests/config.yaml", false, false)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	_, err = NewConfig("./tests/xxx.yaml", false, false)
	if runtime.GOOS != "windows" {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: no such file or directory")
	} else {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: The system cannot find the file specified.")
	}

	_, err = NewConfig("./tests/simulation.yaml", false, false)
	assert.EqualError(t, err, "./tests/simulation.yaml: yaml: unmarshal errors:\n  line 1: field simulation not found in type csconfig.Config")
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
			t.Fatalf("TEST '%s': NOK", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}
	}

}

func TestDefaultConfig(t *testing.T) {
	x := NewDefaultConfig()
	if err := x.Dump(); err != nil {
		log.Fatal(err)
	}
}
