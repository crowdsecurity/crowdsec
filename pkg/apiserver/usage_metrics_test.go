package apiserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
)

func TestLPMetrics(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                 string
		body                 string
		expectedStatusCode   int
		expectedResponse     string
		expectedMetricsCount int
		expectedOSName       string
		expectedOSVersion    string
		expectedFeatureFlags string
		authType             string
	}{
		{
			name: "empty metrics for LP",
			body: `{
			}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   "Missing log processor data",
			authType:           PASSWORD,
		},
		{
			name: "basic metrics with empty dynamic metrics for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedResponse:     "",
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			expectedFeatureFlags: "a,b,c",
			authType:             PASSWORD,
		},
		{
			name: "basic metrics with dynamic metrics for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [{"meta":{"utc_now_timestamp":42, "window_size_seconds": 42}, "items": [{"name": "foo", "value": 42, "unit": "bla"}] }, {"meta":{"utc_now_timestamp":43, "window_size_seconds": 42}, "items": [{"name": "foo", "value": 42, "unit": "bla"}] }],
		"feature_flags": ["a", "b", "c"],
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedResponse:     "",
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			expectedFeatureFlags: "a,b,c",
			authType:             PASSWORD,
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
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   "Missing remediation component data",
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
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedResponse:     "",
			expectedMetricsCount: 1,
			expectedFeatureFlags: "a,b,c",
			authType:             PASSWORD,
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
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: http.StatusUnprocessableEntity,
			expectedResponse:   "log_processors.0.datasources in body is required",
			authType:           PASSWORD,
		},
		{
			name: "missing feature flags for LP",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			authType:             PASSWORD,
		},
		{
			name: "missing OS name",
			body: `
{
	"log_processors": [
	{
		"version": "1.42",
		"os": {"version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"],
		"datasources": {"file": 42},
		"hub_items": {}
	}
	]
}`,
			expectedStatusCode: http.StatusUnprocessableEntity,
			expectedResponse:   "log_processors.0.os.name in body is required",
			authType:           PASSWORD,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lapi := SetupLAPITest(t, ctx)

			dbClient, err := database.NewClient(ctx, lapi.DBConfig)
			if err != nil {
				t.Fatalf("unable to create database client: %s", err)
			}

			w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/usage-metrics", strings.NewReader(tt.body), tt.authType)

			assert.Equal(t, tt.expectedStatusCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedResponse)

			machine, _ := dbClient.QueryMachineByID(ctx, "test")
			metrics, _ := dbClient.GetLPUsageMetricsByMachineID(ctx, "test")

			assert.Len(t, metrics, tt.expectedMetricsCount)
			assert.Equal(t, tt.expectedOSName, machine.Osname)
			assert.Equal(t, tt.expectedOSVersion, machine.Osversion)
			assert.Equal(t, tt.expectedFeatureFlags, machine.Featureflags)

			if len(metrics) > 0 {
				assert.Equal(t, "test", metrics[0].GeneratedBy)
				assert.Equal(t, metric.GeneratedType("LP"), metrics[0].GeneratedType)
			}
		})
	}
}

func TestRCMetrics(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                 string
		body                 string
		expectedStatusCode   int
		expectedResponse     string
		expectedMetricsCount int
		expectedOSName       string
		expectedOSVersion    string
		expectedFeatureFlags string
		authType             string
	}{
		{
			name: "empty metrics for RC",
			body: `{
			}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   "Missing remediation component data",
			authType:           APIKEY,
		},
		{
			name: "basic metrics with empty dynamic metrics for RC",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"]
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedResponse:     "",
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			expectedFeatureFlags: "a,b,c",
			authType:             APIKEY,
		},
		{
			name: "basic metrics with dynamic metrics for RC",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [{"meta":{"utc_now_timestamp":42, "window_size_seconds": 42}, "items": [{"name": "foo", "value": 42, "unit": "bla"}] }, {"meta":{"utc_now_timestamp":43, "window_size_seconds": 42}, "items": [{"name": "foo", "value": 42, "unit": "bla"}] }],
		"feature_flags": ["a", "b", "c"]
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedResponse:     "",
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			expectedFeatureFlags: "a,b,c",
			authType:             APIKEY,
		},
		{
			name: "wrong auth type for RC",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"]
	}
	]
}`,
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   "Missing log processor data",
			authType:           PASSWORD,
		},
		{
			name: "missing OS field for RC",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"]
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedResponse:     "",
			expectedMetricsCount: 1,
			expectedFeatureFlags: "a,b,c",
			authType:             APIKEY,
		},
		{
			name: "missing feature flags for RC",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"os": {"name":"foo", "version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": []
	}
	]
}`,
			expectedStatusCode:   http.StatusCreated,
			expectedMetricsCount: 1,
			expectedOSName:       "foo",
			expectedOSVersion:    "42",
			authType:             APIKEY,
		},
		{
			name: "missing OS name",
			body: `
{
	"remediation_components": [
	{
		"version": "1.42",
		"os": {"version": "42"},
		"utc_startup_timestamp": 42,
		"metrics": [],
		"feature_flags": ["a", "b", "c"]
	}
	]
}`,
			expectedStatusCode: http.StatusUnprocessableEntity,
			expectedResponse:   "remediation_components.0.os.name in body is required",
			authType:           APIKEY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lapi := SetupLAPITest(t, ctx)

			dbClient, err := database.NewClient(ctx, lapi.DBConfig)
			if err != nil {
				t.Fatalf("unable to create database client: %s", err)
			}

			w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/usage-metrics", strings.NewReader(tt.body), tt.authType)

			assert.Equal(t, tt.expectedStatusCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedResponse)

			bouncer, _ := dbClient.SelectBouncerByName(ctx, "test")
			metrics, _ := dbClient.GetBouncerUsageMetricsByName(ctx, "test")

			assert.Len(t, metrics, tt.expectedMetricsCount)
			assert.Equal(t, tt.expectedOSName, bouncer.Osname)
			assert.Equal(t, tt.expectedOSVersion, bouncer.Osversion)
			assert.Equal(t, tt.expectedFeatureFlags, bouncer.Featureflags)

			if len(metrics) > 0 {
				assert.Equal(t, "test", metrics[0].GeneratedBy)
				assert.Equal(t, metric.GeneratedType("RC"), metrics[0].GeneratedType)
			}
		})
	}
}
