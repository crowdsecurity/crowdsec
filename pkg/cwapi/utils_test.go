package cwapi

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const configFile = "./tests/api_config.yaml"
const apiVersion = "v1"
const apiURL = "https://my_test_endpoint"

var apiBaseURL = fmt.Sprintf("%s/%s/", apiURL, apiVersion)

var httpClientMock = &http.Client{
	Transport: newMockTransport(),
	Timeout:   time.Second * 20,
}

type mockTransport struct {
	nbTryTokenOK  int // to test token expiration
	nbTryTokenNOK int
}

func newMockTransport() http.RoundTripper {
	return &mockTransport{}
}

func newMockClient() *http.Client {
	return &http.Client{
		Transport: newMockTransport(),
		Timeout:   time.Second * 20,
	}
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
	switch req.URL.Path {
	case "/v1/signin":
		responseBody = `{"statusCode": 200, "message": "crowdsec_api_token"}`
		statusCode = 200
	case "/v1/register":
		responseBody = `{"statusCode": 200, "message": "OK"}`
		statusCode = 200
	case "/v1/signals":
		responseBody = `{"statusCode": 200, "message": "OK"}`
		statusCode = 200
	case "/v1/signals_token_expired":
		if t.nbTryTokenOK == 0 {
			responseBody = `{"statusCode": 200, "message": "crowdsec_api_token"}`
			statusCode = 401
			t.nbTryTokenOK++
		} else {
			responseBody = `{"statusCode": 200, "message": "OK"}`
			statusCode = 200
		}
	case "/v1/signals_token_renew_fail":
		if t.nbTryTokenNOK == 0 {
			responseBody = `{"statusCode": 200, "message": "crowdsec_api_token"}`
			statusCode = 401
			t.nbTryTokenNOK++
		} else {
			responseBody = `{"statusCode": 500, "message": "token expired"}`
			statusCode = 500
		}
	case "/v1/signals_bad_response_code":
		responseBody = `{"statusCode": 200, "message": "OK"}`
		statusCode = 500
	case "/v1/enroll":
		responseBody = `{"statusCode": 200, "message": "OK"}`
		statusCode = 200
	case "/v1/resetpassword":
		responseBody = `{"statusCode": 200, "message": "password updated successfully"}`
		statusCode = 200
	case "/v1/resetpassword_unknown_user":
		responseBody = `{"statusCode": 500, "message": "User not found"}`
		statusCode = 200
	case "/v1/unknown_path":
		statusCode = 404
		responseBody = `{"error": "unknown URI"}`
	case "/v1/malformed_response":
		statusCode = 200
		responseBody = `{"statusCode" : 200, "msg" : "api_token"`
	case "/v1/bad_response":
		statusCode = 200
		responseBody = `{"statusCode" : 200, "msg" : "api_token"}`
	}
	response.StatusCode = statusCode
	response.Body = ioutil.NopCloser(strings.NewReader(responseBody))
	return response, nil
}
