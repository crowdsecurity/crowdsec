package cwapi

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/dghubble/sling"
	log "github.com/sirupsen/logrus"
)

var signalList = []types.Event{
	{
		Overflow: types.SignalOccurence{
			Scenario:                            "crowdsec/test",
			Bucket_id:                           "1234",
			Events_count:                        1,
			Events_sequence:                     []types.EventSequence{},
			Start_at:                            time.Now(),
			BanApplications:                     []types.BanApplication{},
			Stop_at:                             time.Now(),
			Source_ip:                           "1.2.3.4",
			Source_range:                        "1.2.3.0/24",
			Source_AutonomousSystemNumber:       "1234",
			Source_AutonomousSystemOrganization: "TestAS",
			Source_Country:                      "FR",
			Dest_ip:                             "1.2.3.5",
			Capacity:                            1,
			Whitelisted:                         false,
			Simulation:                          false,
		},
	},
	{
		Overflow: types.SignalOccurence{
			Scenario:                            "crowdsec/test",
			Bucket_id:                           "1235",
			Events_count:                        1,
			Events_sequence:                     []types.EventSequence{},
			Start_at:                            time.Now(),
			BanApplications:                     []types.BanApplication{},
			Stop_at:                             time.Now(),
			Source_ip:                           "1.2.3.5",
			Source_range:                        "1.2.3.0/24",
			Source_AutonomousSystemNumber:       "1234",
			Source_AutonomousSystemOrganization: "TestAS",
			Source_Country:                      "FR",
			Dest_ip:                             "1.2.3.6",
			Capacity:                            1,
			Whitelisted:                         false,
			Simulation:                          false,
		},
	},
}

func TestPushSignal(t *testing.T) {

	tests := []struct {
		name        string
		givenAPICtx *ApiCtx
		expectedErr bool
	}{
		{
			name:        "basic api push signal",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush: signalList,
				Http:   sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal unknown api PATH",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "unknown_path",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush: signalList,
				Http:   sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal malformed response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "malformed_response",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush: signalList,
				Http:   sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal bad response",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "bad_response",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush: signalList,
				Http:   sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal empty signal list",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush: []types.Event{},
				Http:   sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal expired token",
			expectedErr: false,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals_token_expired",
				SigninPath:  "signin",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush:       signalList,
				tokenExpired: false,
				Http:         sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal unable to renew expired token",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals_token_renew_fail",
				SigninPath:  "signin",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush:       signalList,
				tokenExpired: false,
				Http:         sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal bad response code",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals_bad_response_code",
				SigninPath:  "signin",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush:       signalList,
				tokenExpired: false,
				Http:         sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
		{
			name:        "api push signal signin while token expired failed",
			expectedErr: true,
			givenAPICtx: &ApiCtx{
				ApiVersion:  "v1",
				PushPath:    "signals_token_expired",
				SigninPath:  "bad_response",
				BaseURL:     "https://my_testendpoint.com",
				CfgUser:     "machine_id",
				CfgPassword: "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				toPush:       signalList,
				tokenExpired: false,
				Http:         sling.New().Client(newMockClient()).Base(apiBaseURL),
			},
		},
	}

	for _, test := range tests {
		err := test.givenAPICtx.pushSignals()
		if !test.expectedErr && err != nil {
			t.Fatalf("test '%s' failed : %s", test.name, err)
		}
		if test.expectedErr && err == nil {
			t.Fatalf("test '%s' should return an err", test.name)
		}
		if test.expectedErr {
			continue
		}
		log.Printf("test '%s' : OK", test.name)
	}

}
