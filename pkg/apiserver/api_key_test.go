package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestAPIKey(t *testing.T) {
	router, config, err := NewAPITest(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	APIKey, err := CreateTestBouncer(config.API.Server.DbConfig)
	if err != nil {
		log.Fatal(err)
	}
	// Login with empty token
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"message\":\"access forbidden\"}", w.Body.String())

	// Login with invalid token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", "a1b2c3d4e5f6")
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"message\":\"access forbidden\"}", w.Body.String())

	// Login with valid token
	w = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodGet, "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())
}
