package exprhelpers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	out, err := HTTPGet(server.URL)
	require.NoError(t, err)

	resp := out.(*HTTPResponse)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "hello", resp.Body)
	assert.Equal(t, "value", resp.Headers.Get("X-Test"))
}

func TestHTTPHead(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should-be-ignored"))
	}))
	defer server.Close()

	out, err := HTTPHead(server.URL)
	require.NoError(t, err)

	resp := out.(*HTTPResponse)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Body)
	assert.Equal(t, "value", resp.Headers.Get("X-Test"))
}

func TestHTTPPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, _ := io.ReadAll(r.Body)
		assert.JSONEq(t, `{"foo":"bar"}`, string(body))

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	out, err := HTTPPost(server.URL, "application/json", `{"foo":"bar"}`)
	require.NoError(t, err)

	resp := out.(*HTTPResponse)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "created", resp.Body)
}

func TestHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "secret", r.Header.Get("X-Api-Key"))

		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, "payload", string(body))

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	headers := map[string]any{"X-Api-Key": "secret"}

	out, err := HTTPRequest(http.MethodPut, server.URL, headers, "payload")
	require.NoError(t, err)

	resp := out.(*HTTPResponse)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.Equal(t, "ok", resp.Body)
}

func TestHTTPRequestError(t *testing.T) {
	_, err := HTTPGet("http://127.0.0.1:0")
	require.Error(t, err)
}

func TestHTTPExprIntegration(t *testing.T) {
	// echoes back method, Content-Type and body so expressions can assert on them
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.Header().Set("X-Content-Type", r.Header.Get("Content-Type"))
		w.Header().Set("X-Api-Key", r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	tests := []struct {
		name    string
		program string
	}{
		{
			name:    "HTTPGet",
			program: "HTTPGet(url).StatusCode == 200 && HTTPGet(url).Headers.Get('X-Method') == 'GET'",
		},
		{
			name:    "HTTPHead",
			program: "HTTPHead(url).StatusCode == 200 && HTTPHead(url).Headers.Get('X-Method') == 'HEAD'",
		},
		{
			name: "HTTPPost with content-type",
			program: `HTTPPost(url, "application/json", '{"foo":"bar"}').Body == '{"foo":"bar"}' && ` +
				`HTTPPost(url, "application/json", "x").Headers.Get("X-Content-Type") == "application/json"`,
		},
		{
			name: "HTTPRequest generic with headers map literal",
			program: `HTTPRequest("PUT", url, {"X-Api-Key": "secret"}, "payload").Body == "payload" && ` +
				`HTTPRequest("PUT", url, {"X-Api-Key": "secret"}, "payload").Headers.Get("X-Method") == "PUT" && ` +
				`HTTPRequest("PUT", url, {"X-Api-Key": "secret"}, "payload").Headers.Get("X-Api-Key") == "secret"`,
		},
		{
			name:    "HTTPRequest empty body",
			program: `HTTPRequest("GET", url, {}, "").StatusCode == 200`,
		},
	}

	env := map[string]any{"url": server.URL}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program, err := expr.Compile(tc.program, GetExprOptions(env)...)
			require.NoError(t, err)

			out, err := expr.Run(program, env)
			require.NoError(t, err)
			assert.Equal(t, true, out)
		})
	}
}
