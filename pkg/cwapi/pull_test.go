package cwapi

import (
	"encoding/json"
	"testing"

	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPullTop(t *testing.T) {

	tests := []struct {
		name           string
		givenAPICtx    *ApiCtx
		expectedErr    bool
		expectedResult string
	}{
		{
			name:        "basic api pull",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PullPath:    "pull",
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
			expectedResult: pullResponse,
		},
		{
			name:        "basic api pull return non 200 Code",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PullPath:    "unknown_path",
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
			expectedResult: pullResponse,
		},
	}

	for _, test := range tests {
		apiResponse := &PullResp{}
		err := json.Unmarshal([]byte(test.expectedResult), apiResponse)
		result, err := test.givenAPICtx.PullTop()
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		if test.expectedErr {
			continue
		}
		assert.Equal(t, apiResponse.Body, result)
		log.Printf("test '%s' : OK", test.name)
	}

}
