package apiserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLPMetrics(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		expectedStatusCode int
		expectedResponse   string
		authType           string
	}{
		{
			name: "empty metrics for LP",
			body: `{
			}`,
			expectedStatusCode: 400,
			expectedResponse:   "Missing log processor data",
			authType:           PASSWORD,
		},
		{
			name: "basic metrics for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"type": "test-bouncer",
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: 201,
			expectedResponse:   "",
			authType:           PASSWORD,
		},
		{
			name: "wrong auth type for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"type": "test-bouncer",
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: 400,
			expectedResponse:   "",
			authType:           APIKEY,
		},
		{
			name: "missing OS field for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"type": "test-bouncer",
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: 201,
			expectedResponse:   "",
			authType:           PASSWORD,
		},
		{
			name: "missing datasources for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"type": "test-bouncer",
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: 422,
			expectedResponse:   "",
			authType:           PASSWORD,
		},
	}

	lapi := SetupLAPITest(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := lapi.RecordResponse(t, http.MethodPost, "/v1/usage-metrics", strings.NewReader(tt.body), tt.authType)

			assert.Equal(t, tt.expectedStatusCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedResponse)

			//TODO: check metrics inside the database
		})
	}

}
