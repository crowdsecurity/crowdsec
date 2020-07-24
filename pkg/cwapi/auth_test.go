package cwapi

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

func assertConfigFileEqual(t *testing.T, filepath1 string, filepath2 string) {
	file1, err := ioutil.ReadFile(filepath1)
	if err != nil {
		t.Fatalf("unable to read file '%s': %s", filepath1, err)
	}
	apiCtx1 := &ApiCtx{}
	if err := yaml.UnmarshalStrict(file1, &apiCtx1); err != nil {
		t.Fatalf("unable to unmarshall configuration file '%s' : %s", filepath1, err)
	}

	file2, err := ioutil.ReadFile(filepath2)
	if err != nil {
		t.Fatalf("unable to read file '%s': %s", filepath2, err)
	}
	apiCtx2 := &ApiCtx{}
	if err := yaml.UnmarshalStrict(file2, &apiCtx2); err != nil {
		t.Fatalf("unable to unmarshall configuration file '%s' : %s", filepath2, err)
	}
	assert.Equal(t, apiCtx1, apiCtx2)
}

func TestWriteConfig(t *testing.T) {
	tests := []struct {
		name          string
		configPath    string
		compareToFile string
		expectedErr   bool
		givenAPICtx   *ApiCtx
	}{
		{
			name:          "basic write config",
			configPath:    "./tests/tmp_api_config.yaml",
			compareToFile: "./tests/api_config.yaml",
			expectedErr:   false,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				PullPath:     "pull",
				PushPath:     "signals",
				SigninPath:   "signin",
				RegisterPath: "register",
				ResetPwdPath: "resetpassword",
				EnrollPath:   "enroll",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "test",
				CfgPassword:  "test",
				Creds: ApiCreds{
					User:     "test",
					Password: "test",
				},
				Muted:     false,
				DebugDump: false,
				Http:      sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
	}

	for _, test := range tests {
		err := test.givenAPICtx.WriteConfig(test.configPath)
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an error", test.name)
		}
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' returned an error", test.name)
		}
		if test.expectedErr {
			continue
		}

		assertConfigFileEqual(t, test.configPath, test.compareToFile)
		os.Remove(test.configPath)
	}

}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name           string
		configPath     string
		expectedErr    bool
		expectedAPICtx *ApiCtx
	}{
		{
			name:        "basic load config",
			configPath:  "./tests/api_config.yaml",
			expectedErr: false,
			expectedAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				PullPath:     "pull",
				PushPath:     "signals",
				SigninPath:   "signin",
				RegisterPath: "register",
				ResetPwdPath: "resetpassword",
				EnrollPath:   "enroll",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "test",
				CfgPassword:  "test",
				Creds: ApiCreds{
					User:     "test",
					Password: "test",
				},
				Muted:     false,
				DebugDump: false,
				Http:      sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "load config with bad api version",
			configPath:  "./tests/api_config_bad_api_version.yaml",
			expectedErr: true,
		},
		{
			name:        "load config with bad format file",
			configPath:  "./tests/api_config_bad_format.yaml",
			expectedErr: true,
		},
	}

	for _, test := range tests {
		apiCtx := &ApiCtx{}
		err := apiCtx.LoadConfig(test.configPath)
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an error", test.name)
		}
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' return an error : %s", test.name, err)
		}
		if test.expectedErr {
			continue
		}
		apiCtx.Http = test.expectedAPICtx.Http // if we don't do that, assert will fail
		assert.Equal(t, test.expectedAPICtx, apiCtx)
	}
}

func TestSignin(t *testing.T) {

	tests := []struct {
		name        string
		givenAPICtx *ApiCtx
		expectedErr bool
	}{
		{
			name:        "basic api signin",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				SigninPath:  "signin",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api signin missing credentials",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				SigninPath:  "signin",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api signin unknown api PATH",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				SigninPath:  "unknown_path",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api signin malformed response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				SigninPath:  "malformed_response",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api signin bad response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				SigninPath:  "bad_response",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
	}

	for _, test := range tests {
		err := test.givenAPICtx.Signin()
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}

func TestRegisterMachine(t *testing.T) {

	tests := []struct {
		name             string
		givenAPICtx      *ApiCtx
		expectedErr      bool
		expectedAPICtx   *ApiCtx
		expectedAPICreds *ApiCreds
	}{
		{
			name:        "basic api register machine",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				RegisterPath: "register",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
			expectedAPICreds: &ApiCreds{
				User:     "machine_id",
				Password: "machine_password",
				Profile:  "crowdsec/test1,crowdsec/test2",
			},
		},
		{
			name:        "api register unknown api PATH",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				RegisterPath: "unknown_path",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api register malformed response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				RegisterPath: "malformed_response",
				BaseURL:      "https://my_testendpoint.com",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http:       sling.New().Client(newMockClient()).Base(apiBaseURL),
				PusherTomb: tomb.Tomb{},
			},
		},
		{
			name:        "api register bad response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				RegisterPath: "bad_response",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
	}

	for _, test := range tests {
		err := test.givenAPICtx.RegisterMachine(test.givenAPICtx.CfgUser, test.givenAPICtx.CfgPassword)
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		if test.expectedAPICreds != nil {
			assert.Equal(t, *test.expectedAPICreds, test.givenAPICtx.Creds)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}

func TestResetPassword(t *testing.T) {

	tests := []struct {
		name             string
		givenAPICtx      *ApiCtx
		expectedErr      bool
		expectedAPICtx   *ApiCtx
		expectedAPICreds *ApiCreds
	}{
		{
			name:        "basic api machine reset password",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				ResetPwdPath: "resetpassword",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "new_machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
			expectedAPICreds: &ApiCreds{
				User:     "machine_id",
				Password: "new_machine_password",
				Profile:  "crowdsec/test1,crowdsec/test2",
			},
		},
		{
			name:        "api reset password unknown api PATH",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				ResetPwdPath: "unknown_path",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api reset password malformed response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				ResetPwdPath: "malformed_response",
				BaseURL:      "https://my_testendpoint.com",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http:       sling.New().Client(newMockClient()).Base(apiBaseURL),
				PusherTomb: tomb.Tomb{},
			},
		},
		{
			name:        "api reset password bad response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				ResetPwdPath: "bad_response",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api reset password unknown user",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:   "v1",
				ResetPwdPath: "resestpassword_unknown_user",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					Profile: "crowdsec/test1,crowdsec/test2",
				},
				Http: sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
	}

	for _, test := range tests {
		err := test.givenAPICtx.ResetPassword(test.givenAPICtx.CfgUser, test.givenAPICtx.CfgPassword)
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		if test.expectedAPICreds != nil {
			assert.Equal(t, *test.expectedAPICreds, test.givenAPICtx.Creds)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
