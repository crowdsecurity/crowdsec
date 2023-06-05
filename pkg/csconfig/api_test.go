package csconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/go-cs-lib/pkg/cstest"
	"github.com/crowdsecurity/go-cs-lib/pkg/ptr"
)

func TestLoadLocalApiClientCfg(t *testing.T) {
	tests := []struct {
		name        string
		input       *LocalApiClientCfg
		expected    *ApiCredentialsCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
			},
			expected: &ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expected:    &ApiCredentialsCfg{},
			expectedErr: "field unknown_key not found in type csconfig.ApiCredentialsCfg",
		},
		{
			name: "invalid configuration filepath",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_lapi-secrets.yaml",
			},
			expected:    nil,
			expectedErr: "open ./tests/nonexist_lapi-secrets.yaml: " + cstest.FileNotFoundMessage,
		},
		{
			name: "valid configuration with insecure skip verify",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
				InsecureSkipVerify:  ptr.Of(false),
			},
			expected: &ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Load()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Credentials)
		})
	}
}

func TestLoadOnlineApiClientCfg(t *testing.T) {
	tests := []struct {
		name        string
		input       *OnlineApiClientCfg
		expected    *ApiCredentialsCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/online-api-secrets.yaml",
			},
			expected: &ApiCredentialsCfg{
				URL:      "http://crowdsec.api",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expected:    &ApiCredentialsCfg{},
			expectedErr: "failed unmarshaling api server credentials",
		},
		{
			name: "missing field configuration",
			input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_online-api-secrets.yaml",
			},
			expected: nil,
		},
		{
			name: "invalid configuration filepath",
			input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_online-api-secrets.yaml",
			},
			expected:    &ApiCredentialsCfg{},
			expectedErr: "failed to read api server credentials",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.Load()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.Credentials)
		})
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
		t.Fatal(err)
	}
	logLevel := log.InfoLevel
	config := &Config{}
	fcontent, err := os.ReadFile("./tests/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	configData := os.ExpandEnv(string(fcontent))
	err = yaml.UnmarshalStrict([]byte(configData), &config)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		input       *Config
		expected    *LocalApiServerCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			input: &Config{
				Self: []byte(configData),
				API: &APICfg{
					Server: &LocalApiServerCfg{
						ListenURI: "http://crowdsec.api",
						OnlineClient: &OnlineApiClientCfg{
							CredentialsFilePath: "./tests/online-api-secrets.yaml",
						},
						ProfilesPath: "./tests/profiles.yaml",
						PapiLogLevel: &logLevel,
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
			expected: &LocalApiServerCfg{
				Enable:    ptr.Of(true),
				ListenURI: "http://crowdsec.api",
				TLS:       nil,
				DbConfig: &DatabaseCfg{
					DbPath:       "./tests/test.db",
					Type:         "sqlite",
					MaxOpenConns: ptr.Of(DEFAULT_MAX_OPEN_CONNS),
				},
				ConsoleConfigPath: DefaultConfigPath("console.yaml"),
				ConsoleConfig: &ConsoleConfig{
					ShareManualDecisions:  ptr.Of(false),
					ShareTaintedScenarios: ptr.Of(true),
					ShareCustomScenarios:  ptr.Of(true),
					ShareContext:          ptr.Of(false),
					ConsoleManagement:     ptr.Of(false),
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
				PapiLogLevel:           &logLevel,
			},
		},
		{
			name: "basic invalid configuration",
			input: &Config{
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
			expected: &LocalApiServerCfg{
				PapiLogLevel: &logLevel,
			},
			expectedErr: "no database configuration provided",
		},
	}

	for idx, test := range tests {
		err := test.input.LoadAPIServer()
		if err == nil && test.expectedErr != "" {
			fmt.Printf("TEST '%s': NOK\n", test.name)
			t.Fatalf("Test number %d/%d expected error, didn't get it", idx+1, len(tests))
		} else if test.expectedErr != "" {
			fmt.Printf("ERR: %+v\n", err)
			if !strings.HasPrefix(fmt.Sprintf("%s", err), test.expectedErr) {
				fmt.Printf("TEST '%s': NOK\n", test.name)
				t.Fatalf("%d/%d expected '%s' got '%s'", idx, len(tests),
					test.expectedErr,
					fmt.Sprintf("%s", err))
			}

			assert.Equal(t, test.expected, test.input.API.Server)
		}
	}
}
