package csconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
			expected: &ApiCredentialsCfg{},
		},
		{
			name: "invalid configuration filepath",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_lapi-secrets.yaml",
			},
			expected: nil,
		},
		{
			name: "valid configuration with insecure skip verify",
			input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
				InsecureSkipVerify:  types.BoolPtr(false),
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
				Enable:    types.BoolPtr(true),
				ListenURI: "http://crowdsec.api",
				TLS:       nil,
				DbConfig: &DatabaseCfg{
					DbPath:       "./tests/test.db",
					Type:         "sqlite",
					MaxOpenConns: types.IntPtr(DEFAULT_MAX_OPEN_CONNS),
				},
				ConsoleConfigPath: DefaultConfigPath("console.yaml"),
				ConsoleConfig: &ConsoleConfig{
					ShareManualDecisions:  types.BoolPtr(false),
					ShareTaintedScenarios: types.BoolPtr(true),
					ShareCustomScenarios:  types.BoolPtr(true),
					ShareContext:          types.BoolPtr(false),
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
				Enable:   types.BoolPtr(true),
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
			},
			expectedErr: "while loading profiles for LAPI",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.LoadAPIServer()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			if tc.expectedErr != "" {
				return
			}

			assert.Equal(t, tc.expected, tc.input.API.Server)
		})
	}
}
