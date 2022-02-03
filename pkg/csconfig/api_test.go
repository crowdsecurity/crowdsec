package csconfig

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestLoadLocalApiClientCfg(t *testing.T) {
	True := true
	tests := []struct {
		name           string
		Input          *LocalApiClientCfg
		expectedResult *ApiCredentialsCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
		},
		{
			name: "invalid configuration filepath",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_lapi-secrets.yaml",
			},
			expectedResult: nil,
		},
		{
			name: "valid configuration with insecure skip verify",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
				InsecureSkipVerify:  &True,
			},
			expectedResult: &ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
	}

	for idx, test := range tests {
		fmt.Printf("TEST '%s'\n", test.name)
		err := test.Input.Load()
		if err == nil && test.err != "" {
			t.Fatalf("%d/%d expected error, didn't get it", idx, len(tests))
		} else if test.err != "" {
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.err) {
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.err,
					fmt.Sprintf("%s", err))
			}
		}

		isOk := assert.Equal(t, test.expectedResult, test.Input.Credentials)
		if !isOk {
			t.Fatalf("test '%s' failed", test.name)
		}

	}
}

func TestLoadOnlineApiClientCfg(t *testing.T) {
	tests := []struct {
		name           string
		Input          *OnlineApiClientCfg
		expectedResult *ApiCredentialsCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/online-api-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{
				URL:      "http://crowdsec.api",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
			err:            "failed unmarshaling api server credentials",
		},
		{
			name: "missing field configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_online-api-secrets.yaml",
			},
			expectedResult: nil,
		},
		{
			name: "invalid configuration filepath",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_online-api-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
			err:            "failed to read api server credentials",
		},
	}

	for idx, test := range tests {
		err := test.Input.Load()
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

		isOk := assert.Equal(t, test.expectedResult, test.Input.Credentials)
		if !isOk {
			t.Fatalf("TEST '%s': NOK", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}

	}
}

func TestLoadAPIServer(t *testing.T) {
	tmpLAPI := &LocalApiServerCfg{
		ProfilesPath: "./tests/profiles.yaml",
	}
	if err := tmpLAPI.LoadProfiles(); err != nil {
		t.Fatalf("loading tmp profiles: %+v", err)
	}

	LogDirFullPath, err := filepath.Abs("./tests")
	if err != nil {
		t.Fatalf(err.Error())
	}

	config := &Config{}
	fcontent, err := ioutil.ReadFile("./tests/config.yaml")
	if err != nil {
		t.Fatalf(err.Error())
	}
	configData := os.ExpandEnv(string(fcontent))
	err = yaml.UnmarshalStrict([]byte(configData), &config)
	if err != nil {
		t.Fatalf(err.Error())
	}
	tests := []struct {
		name           string
		Input          *Config
		expectedResult *LocalApiServerCfg
		err            string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				Self: []byte(configData),
				API: &APICfg{
					Server: &LocalApiServerCfg{
						ListenURI: "http://crowdsec.api",
						OnlineClient: &OnlineApiClientCfg{
							CredentialsFilePath: "./tests/online-api-secrets.yaml",
						},
						ProfilesPath: "./tests/profiles.yaml",
					},
				},
				DbConfig: &DatabaseCfg{
					Type:   "sqlite",
					DbPath: "./tests/test.db",
				},
				Common: &CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &LocalApiServerCfg{
				ListenURI: "http://crowdsec.api",
				TLS:       nil,
				DbConfig: &DatabaseCfg{
					DbPath: "./tests/test.db",
					Type:   "sqlite",
				},
				ConsoleConfigPath: DefaultConfigPath("console.yaml"),
				ConsoleConfig: &ConsoleConfig{
					ShareManualDecisions:  types.BoolPtr(false),
					ShareTaintedScenarios: types.BoolPtr(true),
					ShareCustomScenarios:  types.BoolPtr(true),
				},
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
				OnlineClient: &OnlineApiClientCfg{
					CredentialsFilePath: "./tests/online-api-secrets.yaml",
					Credentials: &ApiCredentialsCfg{
						URL:      "http://crowdsec.api",
						Login:    "test",
						Password: "testpassword",
					},
				},
				Profiles:               tmpLAPI.Profiles,
				ProfilesPath:           "./tests/profiles.yaml",
				UseForwardedForHeaders: false,
			},
			err: "",
		},
		{
			name: "basic valid configuration",
			Input: &Config{
				Self: []byte(configData),
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
				Common: &CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &LocalApiServerCfg{
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
			},
			err: "while loading profiles for LAPI",
		},
	}

	for idx, test := range tests {
		err := test.Input.LoadAPIServer()
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

		isOk := assert.Equal(t, test.expectedResult, test.Input.API.Server)
		if !isOk {
			t.Fatalf("TEST '%s': NOK", test.name)
		} else {
			fmt.Printf("TEST '%s': OK\n", test.name)
		}

	}
}
