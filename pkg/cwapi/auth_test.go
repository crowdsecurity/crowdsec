package cwapi

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/dghubble/sling"
	"gopkg.in/tomb.v2"
)

const configFile = "./tests/api_config.yaml"
const apiVersion = "v1"
const apiURL = "https://my_test_endpoint"

var apiBaseURL = fmt.Sprintf("%s/%s/", apiURL, apiVersion)

var httpClientMock = &http.Client{
	Transport: newMockTransport(),
}

type mockTransport struct{}

func newMockTransport() http.RoundTripper {
	return &mockTransport{}
}

// Implement http.RoundTripper
func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var responseBody string
	var statusCode int
	// Create mocked http.Response
	response := &http.Response{
		Header:  make(http.Header),
		Request: req,
	}
	response.Header.Set("Content-Type", "application/json")
	if req.URL.Path == "/v1/signin" {
		responseBody = `{"statusCode": 200, "message": "crowdsec_api_token"}`
		statusCode = 200
	}
	response.StatusCode = statusCode
	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
	return response, nil
}

func TestSignin(t *testing.T) {

	tests := []struct {
		apiCtx *ApiCtx
		err    error
	}{
		{
			apiCtx: &ApiCtx{
				ApiVersion:   "v1",
				PullPath:     "pull",
				PushPath:     "signals",
				SigninPath:   "signin",
				RegisterPath: "register",
				ResetPwdPath: "resetpassword",
				EnrollPath:   "enroll",
				BaseURL:      "https://my_testendpoint.com",
				CfgUser:      "machine_id",
				CfgPassword:  "machine_password",
				Creds: ApiCreds{
					User:     "machine_id",
					Password: "machine_password",
					Profile:  "crowdsec/test1,crowdsec/test2",
				},
				Muted:      false,
				DebugDump:  false,
				Http:       sling.New().Client(httpClientMock).Base(apiBaseURL),
				PusherTomb: tomb.Tomb{},
			},
		},
	}

	for _, test := range tests {
		if err := test.apiCtx.Signin(); err != nil {
			t.Fatalf(err.Error())
		}
	}

}

/*func TestRegister(t *testing.T) {
	prepTest()

	if err := apiCtx.RegisterMachine(); err != nil {
		t.Fatalf(err.Error())
	}
}
*/
