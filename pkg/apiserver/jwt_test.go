package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogin(t *testing.T) {
	ctx := t.Context()
	router, config := NewAPITest(t, ctx)

	body := CreateTestMachine(t, ctx, router, "")

	// Login with machine not validated yet
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":401,"message":"machine test not validated"}`, w.Body.String())

	// Login with machine not exist
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(`{"machine_id": "test1", "password": "test1"}`))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":401,"message":"ent: machine not found"}`, w.Body.String())

	// Login with invalid body
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader("test"))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":401,"message":"missing: invalid character 'e' in literal true (expecting 'r')"}`, w.Body.String())

	// Login with invalid format
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(`{"machine_id": "test1"}`))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":401,"message":"validation failure list:\npassword in body is required"}`, w.Body.String())

	// Validate machine
	ValidateMachine(t, ctx, "test", config.API.Server.DbConfig)

	// Login with invalid password
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(`{"machine_id": "test", "password": "test1"}`))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code)
	assert.JSONEq(t, `{"code":401,"message":"incorrect Username or Password"}`, w.Body.String())

	// Login with valid machine
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"token"`)
	assert.Contains(t, w.Body.String(), `"expire"`)

	// Login with valid machine + scenarios
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(`{"machine_id": "test", "password": "test", "scenarios": ["crowdsecurity/test", "crowdsecurity/test2"]}`))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"token"`)
	assert.Contains(t, w.Body.String(), `"expire"`)
}
