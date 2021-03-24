package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCommon(t *testing.T) {
	PidDirFullPath, err := filepath.Abs("./tests/")
	if err != nil {
		t.Fatalf(err.Error())
	}

	LogDirFullPath, err := filepath.Abs("./tests/log/")
	if err != nil {
		t.Fatalf(err.Error())
	}

	WorkingDirFullPath, err := filepath.Abs("./tests")
	if err != nil {
		t.Fatalf(err.Error())
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
				PidDir:     PidDirFullPath,
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
				PidDir:    PidDirFullPath,
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
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.Common)
		if !isOk {
			fmt.Printf("TEST: '%v' failed", test.name)
			t.Fatal()
		}
	}
}
