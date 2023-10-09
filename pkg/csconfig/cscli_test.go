package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCSCLI(t *testing.T) {
	hubFullPath, err := filepath.Abs("./hub")
	if err != nil {
		t.Fatal(err)
	}

	dataFullPath, err := filepath.Abs("./data")
	if err != nil {
		t.Fatal(err)
	}

	configDirFullPath, err := filepath.Abs("./testdata")
	if err != nil {
		t.Fatal(err)
	}

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *CscliCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./testdata",
					DataDir:      "./data",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedResult: &CscliCfg{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: &CscliCfg{},
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadCSCLI()
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

		isOk := assert.Equal(t, test.expectedResult, test.Input.Cscli)
		if !isOk {
			t.Fatalf("TEST '%s': NOK", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}
	}
}
