package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/ptr"
)

func TestCreateMachine(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	// Create machine with invalid format
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader("test"))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"message":"invalid character 'e' in literal true (expecting 'r')"}`, w.Body.String())

	// Create machine with invalid input
	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(`{"test": "test"}`))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.JSONEq(t, `{"message":"validation failure list:\nmachine_id in body is required\npassword in body is required"}`, w.Body.String())

	// Create machine
	b, err := json.Marshal(MachineTest)
	require.NoError(t, err)

	body := string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "", w.Body.String())
}

func TestCreateMachineWithForwardedFor(t *testing.T) {
	ctx := t.Context()
	router, config := NewAPITestForwardedFor(t)
	router.TrustedPlatform = "X-Real-IP"

	// Create machine
	b, err := json.Marshal(MachineTest)
	require.NoError(t, err)

	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Real-Ip", "1.1.1.1")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip := GetMachineIP(t, *MachineTest.MachineID, config.API.Server.DbConfig)

	assert.Equal(t, "1.1.1.1", ip)
}

func TestCreateMachineWithForwardedForNoConfig(t *testing.T) {
	ctx := t.Context()
	router, config := NewAPITest(t, ctx)

	// Create machine
	b, err := json.Marshal(MachineTest)
	require.NoError(t, err)

	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Real-IP", "1.1.1.1")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip := GetMachineIP(t, *MachineTest.MachineID, config.API.Server.DbConfig)

	// For some reason, the IP is empty when running tests
	// if no forwarded-for headers are present
	assert.Equal(t, "", ip)
}

func TestCreateMachineWithoutForwardedFor(t *testing.T) {
	ctx := t.Context()
	router, config := NewAPITestForwardedFor(t)

	// Create machine
	b, err := json.Marshal(MachineTest)
	require.NoError(t, err)

	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "", w.Body.String())

	ip := GetMachineIP(t, *MachineTest.MachineID, config.API.Server.DbConfig)

	// For some reason, the IP is empty when running tests
	// if no forwarded-for headers are present
	assert.Equal(t, "", ip)
}

func TestCreateMachineAlreadyExist(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	body := CreateTestMachine(t, ctx, router, "")

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"message":"user 'test': user already exist"}`, w.Body.String())
}

func TestAutoRegistration(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	// Invalid registration token / valid source IP
	regReq := MachineTest
	regReq.RegistrationToken = invalidRegistrationToken
	b, err := json.Marshal(regReq)
	require.NoError(t, err)

	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "127.0.0.1:4242"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Invalid registration token / invalid source IP
	regReq = MachineTest
	regReq.RegistrationToken = invalidRegistrationToken
	b, err = json.Marshal(regReq)
	require.NoError(t, err)

	body = string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "42.42.42.42:4242"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// valid registration token / invalid source IP
	regReq = MachineTest
	regReq.RegistrationToken = validRegistrationToken
	b, err = json.Marshal(regReq)
	require.NoError(t, err)

	body = string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "42.42.42.42:4242"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Valid registration token / valid source IP
	regReq = MachineTest
	regReq.RegistrationToken = validRegistrationToken
	b, err = json.Marshal(regReq)
	require.NoError(t, err)

	body = string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "127.0.0.1:4242"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)

	// No token / valid source IP
	regReq = MachineTest
	regReq.MachineID = ptr.Of("test2")
	b, err = json.Marshal(regReq)
	require.NoError(t, err)

	body = string(b)

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
	req.RemoteAddr = "127.0.0.1:4242"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}
