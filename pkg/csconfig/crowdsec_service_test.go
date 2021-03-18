package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCrowdsec(t *testing.T) {
	acquisFullPath, err := filepath.Abs("./tests/acquis.yaml")
	if err != nil {
		t.Fatalf(err.Error())
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *CrowdsecServiceCfg
		err            string
	}{
		{
			name: "basic valid simulation",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            "./tests",
				DataDir:              "./data",
				HubDir:               "./hub",
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath},
			},
		},
		{
			name: "basic valid simulation with acquisition dir",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &APICfg{
					Client: &LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis.yaml",
					AcquisitionDirPath:  "./tests/acquis/",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            "./tests",
				DataDir:              "./data",
				HubDir:               "./hub",
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath},
			},
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadCrowdsec()
		if err == nil && test.err != "" {
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.Crowdsec)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}

	}
}
