package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIKey(t *testing.T) {
	ctx := t.Context()
	router, config := NewAPITest(t, ctx)

	APIKey, _ := CreateTestBouncer(t, ctx, config.API.Server.DbConfig)

	// Login with empty token
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"message":"access forbidden"}`, w.Body.String())

	// Login with invalid token
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", "a1b2c3d4e5f6")
	req.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"message":"access forbidden"}`, w.Body.String())

	// Login with valid token
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	req.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// Login with valid token from another IP
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	req.RemoteAddr = "4.3.2.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// Make the requests multiple times to make sure we only create one
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	req.RemoteAddr = "4.3.2.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// Use the original bouncer again
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	req.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// Check if our second bouncer was properly created
	bouncers := GetBouncers(t, config.API.Server.DbConfig)

	assert.Len(t, bouncers, 2)
	assert.Equal(t, "test@4.3.2.1", bouncers[1].Name)
	assert.Equal(t, bouncers[0].APIKey, bouncers[1].APIKey)
	assert.Equal(t, bouncers[0].AuthType, bouncers[1].AuthType)
	assert.False(t, bouncers[0].AutoCreated)
	assert.True(t, bouncers[1].AutoCreated)
}
