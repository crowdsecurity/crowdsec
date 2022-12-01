package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCommon(t *testing.T) {
	pidDirPath := "./tests"
	LogDirFullPath, err := filepath.Abs("./tests/log/")
	if err != nil {
		t.Fatal(err)
	}

	WorkingDirFullPath, err := filepath.Abs("./tests")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *CommonCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				Common: &CommonCfg{
					Daemonize:  true,
					PidDir:     "./tests",
					LogMedia:   "file",
					LogDir:     "./tests/log/",
					WorkingDir: "./tests/",
				},
			},
			expectedResult: &CommonCfg{
				Daemonize:  true,
				PidDir:     pidDirPath,
				LogMedia:   "file",
				LogDir:     LogDirFullPath,
				WorkingDir: WorkingDirFullPath,
			},
		},
		{
			name: "empty working dir",
			Input: &Config{
				Common: &CommonCfg{
					Daemonize: true,
					PidDir:    "./tests",
					LogMedia:  "file",
					LogDir:    "./tests/log/",
				},
			},
			expectedResult: &CommonCfg{
				Daemonize: true,
				PidDir:    pidDirPath,
				LogMedia:  "file",
				LogDir:    LogDirFullPath,
			},
		},
		{
			name:           "no common",
			Input:          &Config{},
			expectedResult: nil,
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadCommon()
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

		isOk := assert.Equal(t, test.expectedResult, test.Input.Common)
		if !isOk {
			t.Fatalf("TEST '%s': NOK", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}
	}
}
