package cwapi

import (
	"testing"

	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

func TestEnroll(t *testing.T) {

	tests := []struct {
		name        string
		givenAPICtx *ApiCtx
		expectedErr bool
		userID      string
	}{
		{
			name:        "basic api user enroll",
			expectedErr: false,
			userID:      "1234",
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				EnrollPath:  "enroll",
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
			name:        "api signin unknown api PATH",
			expectedErr: true,
			userID:      "1234",
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				EnrollPath:  "unknown_path",
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
			userID:      "1234",
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				EnrollPath:  "malformed_response",
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
			userID:      "1234",
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				EnrollPath:  "bad_response",
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
		err := test.givenAPICtx.Enroll(test.userID)
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
