package csconfig

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCrowdsec(t *testing.T) {
	falseBoolPtr := false
	acquisFullPath, err := filepath.Abs("./tests/acquis.yaml")
	if err != nil {
		t.Fatalf(err.Error())
	}

	acquisInDirFullPath, err := filepath.Abs("./tests/acquis/acquis.yaml")
	if err != nil {
		t.Fatalf(err.Error())
	}

	acquisDirFullPath, err := filepath.Abs("./tests/acquis")
	if err != nil {
		t.Fatalf(err.Error())
	}

	hubFullPath, err := filepath.Abs("./hub")
	if err != nil {
		t.Fatalf(err.Error())
	}

	dataFullPath, err := filepath.Abs("./data")
	if err != nil {
		t.Fatalf(err.Error())
	}

	configDirFullPath, err := filepath.Abs("./tests")
	if err != nil {
		t.Fatalf(err.Error())
	}

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
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
			name: "basic valid configuration",
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
					SimulationFilePath:  "./tests/simulation.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "basic valid configuration with acquisition dir",
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
					SimulationFilePath:  "./tests/simulation.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				AcquisitionDirPath:   acquisDirFullPath,
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath, acquisInDirFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "no acquisition file and dir",
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
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedResult: &CrowdsecServiceCfg{
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				SimulationConfig: &SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "non existing acquisition file",
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
					AcquisitionFilePath: "./tests/acquis_not_exist.yaml",
				},
			},
			expectedResult: &CrowdsecServiceCfg{
				AcquisitionFilePath:  "./tests/acquis_not_exist.yaml",
				BucketsRoutinesCount: 0,
				ParserRoutinesCount:  0,
				OutputRoutinesCount:  0,
			},
		},
		{
			name: "agent disabled",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
			},
			expectedResult: nil,
		},
	}

	for idx, test := range tests {
		fmt.Printf("TEST '%s'\n", test.name)
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
