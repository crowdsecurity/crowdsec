package apivalidation

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3filter"
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

			err = rv.LoadSchema(tt.ref, string(schemaBytes), nil)
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
		request     func(t *testing.T) *http.Request
	}{
		{
			name:        "invalid ref",
			schemaName:  "basic",
			ref:         "invalid",
			wantErr:     true,
			expectedErr: "no matching operation was found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com", http.NoBody)
				return req
			},
		},
		{
			name:       "valid request",
			schemaName: "basic",
			ref:        "basic",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/ping", http.NoBody)
				return req
			},
		},
		{
			name:       "basic auth - valid header",
			schemaName: "basic_auth",
			ref:        "basic_auth",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				req.SetBasicAuth("foo", "bar")
				return req
			},
		},
		{
			name:        "basic auth - missing header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "authorization header not found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				return req
			},
		},
		{
			name:        "basic auth - invalid header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "authorization header does not start with 'Basic '",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "basic auth - multiple headers",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "multiple Authorization headers found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
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

			err = rv.LoadSchema(tt.ref, string(schemaBytes), nil)
			require.NoError(t, err)

			err = rv.ValidateRequest(t.Context(), tt.ref, tt.request(t))
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
		request     func(t *testing.T) *http.Request
	}{
		{
			name:       "basic auth - valid header",
			schemaName: "basic_auth",
			ref:        "basic_auth",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				req.SetBasicAuth("foo", "bar")
				return req
			},
		},
		{
			name:        "basic auth - missing header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "authorization header not found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				return req
			},
		},
		{
			name:        "basic auth - invalid header",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "authorization header does not start with 'Basic '",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "basic auth - multiple headers",
			schemaName:  "basic_auth",
			ref:         "basic_auth",
			wantErr:     true,
			expectedErr: "multiple Authorization headers found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/basic", http.NoBody)
				req.Header["Authorization"] = []string{"Basic foo", "Basic bar"}
				return req
			},
		},
		{
			name:       "bearer token - valid header",
			schemaName: "bearer_auth",
			ref:        "bearer_auth",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/bearer", http.NoBody)
				req.Header.Set("Authorization", "Bearer foo")
				return req
			},
		},
		{
			name:        "bearer token - missing header",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "authorization header not found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/bearer", http.NoBody)
				return req
			},
		},
		{
			name:        "bearer token - invalid header",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "authorization header does not start with 'Bearer '",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/bearer", http.NoBody)
				req.Header.Set("Authorization", "asd")
				return req
			},
		},
		{
			name:        "bearer token - multiple headers",
			schemaName:  "bearer_auth",
			ref:         "bearer_auth",
			wantErr:     true,
			expectedErr: "multiple Authorization headers found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/bearer", http.NoBody)
				req.Header["Authorization"] = []string{"Bearer foo", "Bearer bar"}
				return req
			},
		},
		{
			name:       "api key - valid header",
			schemaName: "api_key",
			ref:        "api_key",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/apikey", http.NoBody)
				req.Header.Set("X-API-key", "foo") //nolint:canonicalheader // intentional: exercise case-insensitive header lookup
				return req
			},
		},
		{
			name:        "api key - missing header",
			schemaName:  "api_key",
			ref:         "api_key",
			wantErr:     true,
			expectedErr: "header x-api-key not found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/apikey", http.NoBody)
				return req
			},
		},
		{
			name:        "api key - multiple headers",
			schemaName:  "api_key",
			ref:         "api_key",
			wantErr:     true,
			expectedErr: "multiple headers with name x-api-key found",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/apikey", http.NoBody)
				req.Header.Add("X-API-Key", "foo") //nolint:canonicalheader // intentional: exercise case-insensitive header lookup
				req.Header.Add("X-api-Key", "bar") //nolint:canonicalheader // intentional: exercise case-insensitive header lookup
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

			err = rv.LoadSchema(tt.ref, string(schemaBytes), nil)
			require.NoError(t, err)

			err = rv.ValidateRequest(t.Context(), tt.ref, tt.request(t))
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestQueryParameterValidation(t *testing.T) {
	tests := []struct {
		name        string
		schemaName  string
		ref         string
		wantErr     bool
		expectedErr string
		request     func(t *testing.T) *http.Request
	}{
		{
			name:       "valid query params - all provided",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&offset=0&status=active&verified=true", http.NoBody)
				return req
			},
		},
		{
			name:       "valid query params - only required",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=50", http.NoBody)
				return req
			},
		},
		{
			name:        "missing required parameter",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'limit' value is required but missing",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users", http.NoBody)
				return req
			},
		},
		{
			name:        "integer below minimum",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'limit' number must be at least 1",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=0", http.NoBody)
				return req
			},
		},
		{
			name:        "integer above maximum",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'limit' number must be at most 100",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=101", http.NoBody)
				return req
			},
		},
		{
			name:        "invalid integer type",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'limit' value abc: an invalid integer",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=abc", http.NoBody)
				return req
			},
		},
		{
			name:        "invalid enum value",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'status' value is not one of the allowed values",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&status=deleted", http.NoBody)
				return req
			},
		},
		{
			name:       "valid enum value",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&status=inactive", http.NoBody)
				return req
			},
		},
		{
			name:       "valid email format",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&email=user@example.com", http.NoBody)
				return req
			},
		},
		{
			name:       "valid boolean - true",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&verified=true", http.NoBody)
				return req
			},
		},
		{
			name:       "valid boolean - false",
			schemaName: "query_params",
			ref:        "query_params",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&verified=false", http.NoBody)
				return req
			},
		},
		{
			name:        "invalid boolean",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'verified' value maybe: an invalid boolean",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&verified=maybe", http.NoBody)
				return req
			},
		},
		{
			name:        "age constraint violation",
			schemaName:  "query_params",
			ref:         "query_params",
			wantErr:     true,
			expectedErr: "field 'age' number must be at most 150",
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/users?limit=10&age=200", http.NoBody)
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

			err = rv.LoadSchema(tt.ref, string(schemaBytes), nil)
			require.NoError(t, err)

			err = rv.ValidateRequest(t.Context(), tt.ref, tt.request(t))
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRequestBodyValidation(t *testing.T) {
	tests := []struct {
		name        string
		schemaName  string
		ref         string
		wantErr     bool
		expectedErr string
		request     func(t *testing.T) *http.Request
	}{
		{
			name:       "valid user creation - all fields",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				body := `{"username":"john_doe","email":"john@example.com","age":25,"role":"user","active":true,"tags":["developer","go"],"metadata":{"team":"backend"}}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "valid user creation - required fields only",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				body := `{"username":"jane_doe","email":"jane@example.com","age":30}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "missing required field - username",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"username\"",
			request: func(t *testing.T) *http.Request {
				body := `{"email":"test@example.com","age":25}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "missing required field - email",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"email\"",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","age":25}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "missing required field - age",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"age\"",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "username too short",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "minimum string length is 3",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"ab","email":"test@example.com","age":25}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "username too long",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "maximum string length is 20",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"this_username_is_way_too_long_and_exceeds_limit","email":"test@example.com","age":25}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "username invalid pattern",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "doesn't match the regular expression",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"user-name!","email":"test@example.com","age":25}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "age below minimum",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "number must be at least 18",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":17}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "age above maximum",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "number must be at most 120",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":121}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "invalid role enum",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "value is not one of the allowed values",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":25,"role":"superuser"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "valid role enum",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":25,"role":"admin"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "wrong type for age",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "value must be an integer",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":"twenty-five"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "wrong type for active",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "value must be a boolean",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":25,"active":"yes"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "additional property not allowed",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"unknown_field\" is unsupported",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":25,"unknown_field":"value"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "invalid JSON",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "EOF",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"testuser","email":"test@example.com","age":25`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "valid product with nested object",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				body := `{"name":"Widget","price":29.99,"currency":"USD","dimensions":{"width":10.5,"height":20.3,"depth":5.1}}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/products", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "product missing required nested field",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"width\"",
			request: func(t *testing.T) *http.Request {
				body := `{"name":"Widget","price":29.99,"dimensions":{"height":20.3}}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/products", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "product negative price",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "number must be at least 0.01",
			request: func(t *testing.T) *http.Request {
				body := `{"name":"Widget","price":-10.00}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/products", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "product invalid currency pattern",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "doesn't match the regular expression",
			request: func(t *testing.T) *http.Request {
				body := `{"name":"Widget","price":29.99,"currency":"usd"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/products", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "valid user update",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    false,
			request: func(t *testing.T) *http.Request {
				body := `{"username":"updated_user","email":"updated@example.com","age":35}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPut, "http://example.com/users/123", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:        "user update with additional property",
			schemaName:  "request_body",
			ref:         "request_body",
			wantErr:     true,
			expectedErr: "property \"extra_field\" is unsupported",
			request: func(t *testing.T) *http.Request {
				body := `{"username":"updated_user","age":35,"extra_field":"not_allowed"}`
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPut, "http://example.com/users/123", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				return req
			},
		},
		{
			name:       "empty request body when required",
			schemaName: "request_body",
			ref:        "request_body",
			wantErr:    true,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/users", http.NoBody)
				req.Header.Set("Content-Type", "application/json")
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

			err = rv.LoadSchema(tt.ref, string(schemaBytes), nil)
			require.NoError(t, err)

			err = rv.ValidateRequest(t.Context(), tt.ref, tt.request(t))
			if tt.wantErr {
				require.Error(t, err)
				if tt.expectedErr != "" {
					require.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRoutePolicy(t *testing.T) {
	tests := []struct {
		name        string
		opts        *SchemaOptions
		request     func(t *testing.T) *http.Request
		wantErr     bool
		expectedErr string
	}{
		{
			name: "unknown path, default policy drops",
			opts: nil,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/unknown", http.NoBody)
				return req
			},
			wantErr:     true,
			expectedErr: "no matching operation was found",
		},
		{
			name: "unknown path, ignore policy passes",
			opts: &SchemaOptions{OnRouteNotFound: RoutePolicyIgnore},
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/unknown", http.NoBody)
				return req
			},
			wantErr: false,
		},
		{
			name: "unknown path, explicit drop policy drops",
			opts: &SchemaOptions{OnRouteNotFound: RoutePolicyDrop},
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodGet, "http://example.com/unknown", http.NoBody)
				return req
			},
			wantErr:     true,
			expectedErr: "no matching operation was found",
		},
		{
			name: "method not allowed, default policy drops",
			opts: nil,
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/ping", http.NoBody)
				return req
			},
			wantErr:     true,
			expectedErr: "method not allowed",
		},
		{
			name: "method not allowed, ignore policy passes",
			opts: &SchemaOptions{OnMethodNotAllowed: RoutePolicyIgnore},
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/ping", http.NoBody)
				return req
			},
			wantErr: false,
		},
		{
			name: "method not allowed with ignore path policy still drops",
			opts: &SchemaOptions{OnRouteNotFound: RoutePolicyIgnore},
			request: func(t *testing.T) *http.Request {
				req, _ := http.NewRequestWithContext(t.Context(),http.MethodPost, "http://example.com/ping", http.NoBody)
				return req
			},
			wantErr:     true,
			expectedErr: "method not allowed",
		},
	}

	logger := log.New().WithField("test", "apivalidation")
	schemaBytes, err := os.ReadFile(filepath.Join(".", "test_schemas", "basic.yaml"))
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := NewRequestValidator(logger)
			err := rv.LoadSchema("basic", string(schemaBytes), tt.opts)
			require.NoError(t, err)

			err = rv.ValidateRequest(t.Context(), "basic", tt.request(t))
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestInvalidRoutePolicy(t *testing.T) {
	logger := log.New().WithField("test", "apivalidation")
	schemaBytes, err := os.ReadFile(filepath.Join(".", "test_schemas", "basic.yaml"))
	require.NoError(t, err)

	rv := NewRequestValidator(logger)
	err = rv.LoadSchema("basic", string(schemaBytes), &SchemaOptions{OnRouteNotFound: "explode"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid route policy")
}

func TestBodyDecoderRegistration(t *testing.T) {
	logger := log.New().WithField("test", "apivalidation")

	t.Run("unknown decoder name errors", func(t *testing.T) {
		rv := NewRequestValidator(logger)
		err := rv.RegisterBodyDecoder("application/foo", "bogus")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown body decoder")
	})

	t.Run("zip decoder is not exposed", func(t *testing.T) {
		rv := NewRequestValidator(logger)
		err := rv.RegisterBodyDecoder("application/zip", "zip")
		require.Error(t, err, "zip must not be registrable via the public helper")
	})

	t.Run("NewRequestValidator re-registers only the default allowlist", func(t *testing.T) {
		_ = NewRequestValidator(logger)

		// Defaults must be present.
		for _, ct := range []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
		} {
			require.NotNil(t, openapi3filter.RegisteredBodyDecoder(ct),
				"default content type %q should be registered after NewRequestValidator", ct)
		}

		// Kin's non-allowlisted defaults must be gone.
		for _, ct := range []string{
			"application/x-yaml",
			"application/yaml",
			"application/zip",
			"text/csv",
			"text/plain",
			"application/octet-stream",
		} {
			require.Nil(t, openapi3filter.RegisteredBodyDecoder(ct),
				"content type %q should not be registered by default", ct)
		}
	})

	t.Run("user-registered decoder becomes available", func(t *testing.T) {
		rv := NewRequestValidator(logger)
		require.Nil(t, openapi3filter.RegisteredBodyDecoder("application/x-yaml"),
			"sanity: yaml should not be registered by default")

		require.NoError(t, rv.RegisterBodyDecoder("application/x-yaml", "yaml"))
		require.NotNil(t, openapi3filter.RegisteredBodyDecoder("application/x-yaml"))

		// Reset for subsequent tests.
		_ = NewRequestValidator(logger)
	})
}
