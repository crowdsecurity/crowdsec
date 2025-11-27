package apivalidation

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestLoadSchema(t *testing.T) {
	tests := []struct {
		name       string
		schemaName string
		ref        string
		wantErr    bool
	}{
		{
			name:       "invalid schema",
			schemaName: "invalid",
			wantErr:    true,
			ref:        "",
		},
		{
			name:       "empty ref",
			schemaName: "basic",
			ref:        "",
			wantErr:    true,
		},
		{
			name:       "valid schema",
			schemaName: "basic",
			ref:        "basic",
			wantErr:    false,
		},
	}

	logger := log.New().WithField("test", "apivalidation")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := NewRequestValidator(logger)
			schemaFile, err := os.Open(filepath.Join(".", "test_schemas", tt.schemaName+".yaml"))
			require.NoError(t, err)
			defer schemaFile.Close()
			schemaBytes, err := io.ReadAll(schemaFile)
			require.NoError(t, err)

			err = rv.LoadSchema(tt.ref, string(schemaBytes))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateRequest(t *testing.T) {

	tests := []struct {
		name        string
		schemaName  string
		ref         string
		wantErr     bool
		expectedErr string
		request     func() *http.Request
	}{
		{
			name:        "invalid ref",
			schemaName:  "basic",
			ref:         "invalid",
			wantErr:     true,
			expectedErr: "no matching operation was found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
				return req
			},
		},
		{
			name:       "valid request",
			schemaName: "basic",
			ref:        "basic",
			wantErr:    false,
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/ping", nil)
				return req
			},
		},
		{
			name:       "basic auth - valid header",
			schemaName: "basic_auth",
			ref:        "basic_auth",
			wantErr:    false,
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.SetBasicAuth("foo", "bar")
				return req
			},
		},
		{
			name:        "basic auth - missing header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header not found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				return req
			},
		},
		{
			name:        "basic auth - invalid header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header does not start with 'Basic '",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "basic auth - multiple headers",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: multiple Authorization headers found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.Header["Authorization"] = []string{"Basic foo", "Basic bar"}
				return req
			},
		},
	}

	logger := log.New().WithField("test", "apivalidation")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := NewRequestValidator(logger)
			schemaFile, err := os.Open(filepath.Join(".", "test_schemas", tt.schemaName+".yaml"))
			require.NoError(t, err)
			defer schemaFile.Close()
			schemaBytes, err := io.ReadAll(schemaFile)
			require.NoError(t, err)

			err = rv.LoadSchema(tt.ref, string(schemaBytes))
			require.NoError(t, err)

			err = rv.ValidateRequest(tt.ref, tt.request())
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSecurityRequirements(t *testing.T) {
	tests := []struct {
		name        string
		schemaName  string
		ref         string
		wantErr     bool
		expectedErr string
		request     func() *http.Request
	}{
		{
			name:       "basic auth - valid header",
			schemaName: "basic_auth",
			ref:        "basic_auth",
			wantErr:    false,
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.SetBasicAuth("foo", "bar")
				return req
			},
		},
		{
			name:        "basic auth - missing header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header not found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				return req
			},
		},
		{
			name:        "basic auth - invalid header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header does not start with 'Basic '",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "basic auth - multiple headers",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: multiple Authorization headers found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/basic", nil)
				req.Header["Authorization"] = []string{"Basic foo", "Basic bar"}
				return req
			},
		},
		{
			name:       "bearer token - valid header",
			schemaName: "bearer_auth",
			ref:        "bearer_auth",
			wantErr:    false,
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/bearer", nil)
				req.Header.Set("Authorization", "Bearer foo")
				return req
			},
		},
		{
			name:        "bearer token - missing header",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header not found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/bearer", nil)
				return req
			},
		},
		{
			name:        "bearer token - invalid header",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: authorization header does not start with 'Bearer '",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/bearer", nil)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "bearer token - multiple headers",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "security requirements failed: multiple Authorization headers found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/bearer", nil)
				req.Header["Authorization"] = []string{"Bearer foo", "Bearer bar"}
				return req
			},
		},
		{
			name:       "api key - valid header",
			schemaName: "api_key",
			ref:        "api_key",
			wantErr:    false,
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/apikey", nil)
				req.Header.Set("X-API-key", "foo")
				return req
			},
		},
		{
			name:        "api key - missing header",
			schemaName:  "api_key",
			ref:         "api_key",
			wantErr:     true,
			expectedErr: "security requirements failed: header x-api-key not found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/apikey", nil)
				return req
			},
		},
		{
			name:        "api key - multiple headers",
			schemaName:  "api_key",
			ref:         "api_key",
			wantErr:     true,
			expectedErr: "security requirements failed: multiple headers with name x-api-key found",
			request: func() *http.Request {
				req, _ := http.NewRequest(http.MethodGet, "http://example.com/apikey", nil)
				req.Header.Add("X-API-Key", "foo")
				req.Header.Add("X-api-Key", "bar")
				return req
			},
		},
	}

	logger := log.New().WithField("test", "apivalidation")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := NewRequestValidator(logger)
			schemaFile, err := os.Open(filepath.Join(".", "test_schemas", tt.schemaName+".yaml"))
			require.NoError(t, err)
			defer schemaFile.Close()
			schemaBytes, err := io.ReadAll(schemaFile)
			require.NoError(t, err)

			err = rv.LoadSchema(tt.ref, string(schemaBytes))
			require.NoError(t, err)

			err = rv.ValidateRequest(tt.ref, tt.request())
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestJWKSValidation(t *testing.T) {
	tests := []struct {
		name        string
		schemaName  string
		ref         string
		wantErr     bool
		expectedErr string
		request     func() *http.Request
	}{}

	logger := log.New().WithField("test", "apivalidation")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := NewRequestValidator(logger)
			schemaFile, err := os.Open(filepath.Join(".", "test_schemas", tt.schemaName+".yaml"))
			require.NoError(t, err)
			defer schemaFile.Close()
			schemaBytes, err := io.ReadAll(schemaFile)
			require.NoError(t, err)

			err = rv.LoadSchema(tt.ref, string(schemaBytes))
			require.NoError(t, err)

			err = rv.ValidateRequest(tt.ref, tt.request())
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
