package csconfig

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadOnlineApiClientCfg(t *testing.T) {
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
