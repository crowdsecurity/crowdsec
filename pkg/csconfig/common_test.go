package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestLoadCommon(t *testing.T) {
	pidDirPath := "./testdata"
	LogDirFullPath, err := filepath.Abs("./testdata/log/")
	require.NoError(t, err)

	WorkingDirFullPath, err := filepath.Abs("./testdata")
	require.NoError(t, err)

	tests := []struct {
		name        string
		input       *Config
		expected    *CommonCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				Common: &CommonCfg{
					Daemonize:  true,
					PidDir:     "./testdata",
					LogMedia:   "file",
					LogDir:     "./testdata/log/",
					WorkingDir: "./testdata/",
				},
			},
			expected: &CommonCfg{
				Daemonize:  true,
				PidDir:     pidDirPath,
				LogMedia:   "file",
				LogDir:     LogDirFullPath,
				WorkingDir: WorkingDirFullPath,
			},
		},
		{
			name: "empty working dir",
			input: &Config{
				Common: &CommonCfg{
					Daemonize: true,
					PidDir:    "./testdata",
					LogMedia:  "file",
					LogDir:    "./testdata/log/",
				},
			},
			expected: &CommonCfg{
				Daemonize: true,
				PidDir:    pidDirPath,
				LogMedia:  "file",
				LogDir:    LogDirFullPath,
			},
		},
		{
			name:        "no common",
			input:       &Config{},
			expected:    nil,
			expectedErr: "no common block provided in configuration file",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadCommon()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Common)
		})
	}
}
