package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logtest "github.com/sirupsen/logrus/hooks/test"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const (
	passwordAuthType = "password"
	apiKeyAuthType   = "apikey"
)

type LAPI struct {
	router     *gin.Engine
	loginResp  models.WatcherAuthResponse
	bouncerKey string
	DBConfig   *csconfig.DatabaseCfg
	DBClient   *database.Client
}

func SetupLAPITest(t *testing.T, ctx context.Context) LAPI {
	t.Helper()
	router, loginResp, config := InitMachineTest(t, ctx)

	APIKey, dbClient := CreateTestBouncer(t, ctx, config.API.Server.DbConfig)

	return LAPI{
		router:     router,
		loginResp:  loginResp,
		bouncerKey: APIKey,
		DBConfig:   config.API.Server.DbConfig,
		DBClient:   dbClient,
	}
}

func (l *LAPI) InsertAlertFromFile(t *testing.T, ctx context.Context, path string) *httptest.ResponseRecorder {
	alertReader := GetAlertReaderFromFile(t, path)
	return l.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", alertReader, "password")
}

func (l *LAPI) RecordResponse(t *testing.T, ctx context.Context, verb string, url string, body *strings.Reader, authType string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, verb, url, body)
	require.NoError(t, err)

	switch authType {
	case apiKeyAuthType:
		req.Header.Add("X-Api-Key", l.bouncerKey)
	case passwordAuthType:
		AddAuthHeaders(req, l.loginResp)
	default:
		t.Fatal("auth type not supported")
	}

	// Port is required for gin to properly parse the client IP
	req.RemoteAddr = "127.0.0.1:1234"

	l.router.ServeHTTP(w, req)

	return w
}

func InitMachineTest(t *testing.T, ctx context.Context) (*gin.Engine, models.WatcherAuthResponse, csconfig.Config) {
	router, config := NewAPITest(t, ctx)
	loginResp := LoginToTestAPI(t, ctx, router, config)

	return router, loginResp, config
}

func LoginToTestAPI(t *testing.T, ctx context.Context, router *gin.Engine, config csconfig.Config) models.WatcherAuthResponse {
	body := CreateTestMachine(t, ctx, router, "")
	ValidateMachine(t, ctx, "test", config.API.Server.DbConfig)

	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers/login", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	loginResp := models.WatcherAuthResponse{}
	err = json.NewDecoder(w.Body).Decode(&loginResp)
	require.NoError(t, err)

	return loginResp
}

func AddAuthHeaders(request *http.Request, authResponse models.WatcherAuthResponse) {
	request.Header.Add("User-Agent", UserAgent)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authResponse.Token))
}

func TestSimulatedAlert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk+simul.json")
	alertContent := GetAlertReaderFromFile(t, "./tests/alert_minibulk+simul.json")
	// exclude decision in simulation mode

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?simulated=false", alertContent, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Ip 91.121.79.178 performed crowdsecurity/ssh-bf (6 events over `)
	assert.NotContains(t, w.Body.String(), `"message":"Ip 91.121.79.179 performed crowdsecurity/ssh-bf (6 events over `)
	// include decision in simulation mode

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?simulated=true", alertContent, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"message":"Ip 91.121.79.178 performed crowdsecurity/ssh-bf (6 events over `)
	assert.Contains(t, w.Body.String(), `"message":"Ip 91.121.79.179 performed crowdsecurity/ssh-bf (6 events over `)
}

func TestCreateAlert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	// Create Alert with invalid format

	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", strings.NewReader("test"), "password")
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"message":"invalid character 'e' in literal true (expecting 'r')"}`, w.Body.String())

	// Create Alert with invalid input
	alertContent := GetAlertReaderFromFile(t, "./tests/invalidAlert_sample.json")

	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", alertContent, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t,
		`{"message":"validation failure list:\n0.scenario in body is required\n0.scenario_hash in body is required\n0.scenario_version in body is required\n0.simulated in body is required\n0.source in body is required"}`,
		w.Body.String())

	// Create Valid Alert
	w = lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, `["1"]`, w.Body.String())
}

func TestCreateAllowlistedAlert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	allowlist, err := lapi.DBClient.CreateAllowList(ctx, "test", "test", "", false)
	require.NoError(t, err)
	added, err := lapi.DBClient.AddToAllowlist(ctx, allowlist, []*models.AllowlistItem{
		{
			Value: "10.0.0.0/24",
		},
		{
			Value:      "192.168.0.0/24",
			Expiration: strfmt.DateTime(time.Now().Add(-time.Hour)), // Expired item
		},
		{
			Value: "127.0.0.1",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, 3, added)

	// Create Alert with allowlisted IP
	alertContent := GetAlertReaderFromFile(t, "./tests/alert_allowlisted.json")
	w := lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", alertContent, "password")
	assert.Equal(t, http.StatusCreated, w.Code)

	// We should have no alert as the IP is allowlisted
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// Create Alert with expired allowlisted IP
	alertContent = GetAlertReaderFromFile(t, "./tests/alert_allowlisted_expired.json")
	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", alertContent, "password")
	assert.Equal(t, http.StatusCreated, w.Code)

	// We should have an alert as the IP is allowlisted but the item is expired
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "192.168.0.42")

	// Create Alert with allowlisted IP but with decisions (manual ban)
	alertContent = GetAlertReaderFromFile(t, "./tests/alert_sample.json")
	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/alerts", alertContent, "password")
	assert.Equal(t, http.StatusCreated, w.Code)

	// We should have an alert as the IP is allowlisted but the alert has decisions
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "127.0.0.1")
}

func TestCreateAlertChannels(t *testing.T) {
	ctx := t.Context()
	apiServer, config := NewAPIServer(t, ctx)
	apiServer.controller.PluginChannel = make(chan models.ProfileAlert)
	err := apiServer.InitController()
	require.NoError(t, err)

	loginResp := LoginToTestAPI(t, ctx, apiServer.router, config)
	lapi := LAPI{router: apiServer.router, loginResp: loginResp}

	var (
		pd models.ProfileAlert
		wg sync.WaitGroup
	)

	wg.Add(1)

	go func() {
		pd = <-apiServer.controller.PluginChannel

		wg.Done()
	}()

	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_ssh-bf.json")
	wg.Wait()
	assert.Len(t, pd.Alert.Decisions, 1)
	apiServer.Close()
}

func TestAlertListFilters(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_ssh-bf.json")
	alertContent := GetAlertReaderFromFile(t, "./tests/alert_ssh-bf.json")

	// bad filter

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?test=test", alertContent, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"message":"filter parameter 'test' is unknown (=test): invalid filter"}`, w.Body.String())

	// get without filters

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	// check alert and decision
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test decision_type filter (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?decision_type=ban", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test decision_type filter (bad value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?decision_type=ratata", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test scope (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?scope=Ip", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test scope (bad value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?scope=rarara", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test scenario (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?scenario=crowdsecurity/ssh-bf", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test scenario (bad value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?scenario=crowdsecurity/nope", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test ip (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?ip=91.121.79.195", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test ip (bad value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?ip=99.122.77.195", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test ip (invalid value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?ip=gruueq", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"message":"ParseAddr(\"gruueq\"): unable to parse IP"}`, w.Body.String())

	// test range (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?range=91.121.79.0/24&contains=false", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test range

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?range=99.122.77.0/24&contains=false", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test range (invalid value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?range=ratata", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"message":"ParseAddr(\"ratata\"): unable to parse IP"}`, w.Body.String())

	// test since (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?since=1h", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test since (ok but yields no results)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?since=1ns", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test since (invalid value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?since=1zuzu", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), `{"message":"while parsing duration: time: unknown unit`)

	// test until (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?until=1ns", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test until (ok but no return)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?until=1m", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test until (invalid value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?until=1zuzu", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), `{"message":"while parsing duration: time: unknown unit`)

	// test simulated (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?simulated=true", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test simulated (ok)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?simulated=false", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test has active decision

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?has_active_decision=true", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"type":"ban","value":"91.121.79.195"`)

	// test has active decision

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?has_active_decision=false", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "null", w.Body.String())

	// test has active decision (invalid value)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?has_active_decision=ratatqata", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"message":"'ratatqata' is not a boolean: strconv.ParseBool: parsing \"ratatqata\": invalid syntax: unable to parse type"}`, w.Body.String())
}

func TestAlertBulkInsert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	// insert a bulk of 20 alerts to trigger bulk insert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_bulk.json")
	alertContent := GetAlertReaderFromFile(t, "./tests/alert_bulk.json")

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", alertContent, "password")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListAlert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	// List Alert with invalid filter

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/alerts?test=test", emptyBody, "password")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"message":"filter parameter 'test' is unknown (=test): invalid filter"}`, w.Body.String())

	// List Alert

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/alerts", emptyBody, "password")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "crowdsecurity/test")
}

func TestCreateAlertErrors(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	alertContent := GetAlertReaderFromFile(t, "./tests/alert_sample.json")

	// test invalid bearer
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/alerts", alertContent)
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", "ratata"))
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// test invalid bearer
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, "/v1/alerts", alertContent)
	require.NoError(t, err)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", lapi.loginResp.Token+"s"))
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteAlert(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Fail Delete Alert
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts", strings.NewReader(""))
	require.NoError(t, err)
	AddAuthHeaders(req, lapi.loginResp)
	req.RemoteAddr = "127.0.0.2:4242"
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"message":"access forbidden from this IP (127.0.0.2)"}`, w.Body.String())

	// Delete Alert
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts", strings.NewReader(""))
	require.NoError(t, err)
	AddAuthHeaders(req, lapi.loginResp)
	req.RemoteAddr = "127.0.0.1:4242"
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestDeleteAlertByID(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Fail Delete Alert
	w := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts/1", strings.NewReader(""))
	require.NoError(t, err)
	AddAuthHeaders(req, lapi.loginResp)
	req.RemoteAddr = "127.0.0.2:4242"
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"message":"access forbidden from this IP (127.0.0.2)"}`, w.Body.String())

	// Delete Alert
	w = httptest.NewRecorder()
	req, err = http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts/1", strings.NewReader(""))
	require.NoError(t, err)
	AddAuthHeaders(req, lapi.loginResp)
	req.RemoteAddr = "127.0.0.1:4242"
	lapi.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestDeleteAlertTrustedIPS(t *testing.T) {
	ctx := t.Context()
	cfg := LoadTestConfig(t)
	// IPv6 mocking doesn't seem to work.
	// cfg.API.Server.TrustedIPs = []string{"1.2.3.4", "1.2.4.0/24", "::"}
	cfg.API.Server.TrustedIPs = []string{"1.2.3.4", "1.2.4.0/24"}
	cfg.API.Server.ListenURI = "::8080"

	logger, _ := logtest.NewNullLogger()
	server, err := NewServer(ctx, cfg.API.Server, logger.WithFields(nil))
	require.NoError(t, err)

	err = server.InitController()
	require.NoError(t, err)

	router, err := server.Router()
	require.NoError(t, err)

	loginResp := LoginToTestAPI(t, ctx, router, cfg)
	lapi := LAPI{
		router:    router,
		loginResp: loginResp,
	}

	assertAlertDeleteFailedFromIP := func(ip string) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts", strings.NewReader(""))

		AddAuthHeaders(req, loginResp)
		req.RemoteAddr = ip + ":1234"

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), fmt.Sprintf(`{"message":"access forbidden from this IP (%s)"}`, ip))
	}

	assertAlertDeletedFromIP := func(ip string) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, "/v1/alerts", strings.NewReader(""))
		AddAuthHeaders(req, loginResp)
		req.RemoteAddr = ip + ":1234"

		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"nbDeleted":"1"}`, w.Body.String())
	}

	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assertAlertDeleteFailedFromIP("4.3.2.1")
	assertAlertDeletedFromIP("1.2.3.4")

	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assertAlertDeletedFromIP("1.2.4.0")
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assertAlertDeletedFromIP("1.2.4.1")
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assertAlertDeletedFromIP("1.2.4.255")

	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")
	assertAlertDeletedFromIP("127.0.0.1")
}
