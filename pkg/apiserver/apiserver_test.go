package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	validRegistrationToken   = "igheethauCaeteSaiyee3LosohPhahze"
	invalidRegistrationToken = "vohl1feibechieG5coh8musheish2auj"
)

var (
	testMachineID = "test"
	testPassword  = strfmt.Password("test")
	MachineTest   = models.WatcherRegistrationRequest{
		MachineID: &testMachineID,
		Password:  &testPassword,
	}
	UserAgent = "crowdsec-test/" + version.Version
	emptyBody = strings.NewReader("")
)

func LoadTestConfig(t *testing.T) csconfig.Config {
	config := csconfig.Config{}
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}

	tempDir, _ := os.MkdirTemp("", "crowdsec_tests")

	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: filepath.Join(tempDir, "ent"),
		Flush:  &flushConfig,
	}
	apiServerConfig := csconfig.LocalApiServerCfg{
		ListenURI:    "http://127.0.0.1:8080",
		LogLevel:     ptr.Of(log.DebugLevel),
		DbConfig:     &dbconfig,
		ProfilesPath: "./tests/profiles.yaml",
		ConsoleConfig: &csconfig.ConsoleConfig{
			ShareManualDecisions:  new(bool),
			ShareTaintedScenarios: new(bool),
			ShareCustomScenarios:  new(bool),
		},
		AutoRegister: &csconfig.LocalAPIAutoRegisterCfg{
			Enable: ptr.Of(true),
			Token:  validRegistrationToken,
			AllowedRanges: []string{
				"127.0.0.1/8",
				"::1/128",
			},
		},
	}

	apiConfig := csconfig.APICfg{
		Server: &apiServerConfig,
	}

	config.API = &apiConfig
	err := config.API.Server.LoadProfiles()
	require.NoError(t, err)

	err = config.API.Server.LoadAutoRegister()
	require.NoError(t, err)

	return config
}

func LoadTestConfigForwardedFor(t *testing.T) csconfig.Config {
	config := csconfig.Config{}
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}

	tempDir, _ := os.MkdirTemp("", "crowdsec_tests")

	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: filepath.Join(tempDir, "ent"),
		Flush:  &flushConfig,
	}
	apiServerConfig := csconfig.LocalApiServerCfg{
		ListenURI:              "http://127.0.0.1:8080",
		DbConfig:               &dbconfig,
		ProfilesPath:           "./tests/profiles.yaml",
		UseForwardedForHeaders: true,
		TrustedProxies:         &[]string{"0.0.0.0/0"},
		ConsoleConfig: &csconfig.ConsoleConfig{
			ShareManualDecisions:  new(bool),
			ShareTaintedScenarios: new(bool),
			ShareCustomScenarios:  new(bool),
		},
	}
	apiConfig := csconfig.APICfg{
		Server: &apiServerConfig,
	}
	config.API = &apiConfig
	err := config.API.Server.LoadProfiles()
	require.NoError(t, err)

	err = config.API.Server.LoadAutoRegister()
	require.NoError(t, err)

	return config
}

func NewAPIServer(t *testing.T, ctx context.Context) (*APIServer, csconfig.Config) {
	config := LoadTestConfig(t)

	os.Remove("./ent")

	apiServer, err := NewServer(ctx, config.API.Server)
	require.NoError(t, err)

	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)

	return apiServer, config
}

func NewAPITest(t *testing.T, ctx context.Context) (*gin.Engine, csconfig.Config) {
	apiServer, config := NewAPIServer(t, ctx)

	err := apiServer.InitController()
	require.NoError(t, err)

	router, err := apiServer.Router()
	require.NoError(t, err)

	return router, config
}

func NewAPITestForwardedFor(t *testing.T) (*gin.Engine, csconfig.Config) {
	ctx := t.Context()
	config := LoadTestConfigForwardedFor(t)

	os.Remove("./ent")

	apiServer, err := NewServer(ctx, config.API.Server)
	require.NoError(t, err)

	err = apiServer.InitController()
	require.NoError(t, err)

	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)

	router, err := apiServer.Router()
	require.NoError(t, err)

	return router, config
}

func ValidateMachine(t *testing.T, ctx context.Context, machineID string, config *csconfig.DatabaseCfg) {
	dbClient, err := database.NewClient(ctx, config)
	require.NoError(t, err)

	err = dbClient.ValidateMachine(ctx, machineID)
	require.NoError(t, err)
}

func GetMachineIP(t *testing.T, machineID string, config *csconfig.DatabaseCfg) string {
	ctx := t.Context()

	dbClient, err := database.NewClient(ctx, config)
	require.NoError(t, err)

	machines, err := dbClient.ListMachines(ctx)
	require.NoError(t, err)

	for _, machine := range machines {
		if machine.MachineId == machineID {
			return machine.IpAddress
		}
	}

	return ""
}

func GetBouncers(t *testing.T, config *csconfig.DatabaseCfg) []*ent.Bouncer {
	ctx := t.Context()

	dbClient, err := database.NewClient(ctx, config)
	require.NoError(t, err)

	bouncers, err := dbClient.ListBouncers(ctx)
	require.NoError(t, err)

	return bouncers
}

func GetAlertReaderFromFile(t *testing.T, path string) *strings.Reader {
	alertContentBytes, err := os.ReadFile(path)
	require.NoError(t, err)

	alerts := make([]*models.Alert, 0)
	err = json.Unmarshal(alertContentBytes, &alerts)
	require.NoError(t, err)

	for _, alert := range alerts {
		*alert.StartAt = time.Now().UTC().Format(time.RFC3339)
		*alert.StopAt = time.Now().UTC().Format(time.RFC3339)
	}

	alertContent, err := json.Marshal(alerts)
	require.NoError(t, err)

	return strings.NewReader(string(alertContent))
}

func readDecisionsGetResp(t *testing.T, resp *httptest.ResponseRecorder) ([]*models.Decision, int) {
	var response []*models.Decision

	require.NotNil(t, resp)

	err := json.Unmarshal(resp.Body.Bytes(), &response)
	require.NoError(t, err)

	return response, resp.Code
}

func readDecisionsErrorResp(t *testing.T, resp *httptest.ResponseRecorder) (map[string]string, int) {
	var response map[string]string

	require.NotNil(t, resp)

	err := json.Unmarshal(resp.Body.Bytes(), &response)
	require.NoError(t, err)

	return response, resp.Code
}

func readDecisionsDeleteResp(t *testing.T, resp *httptest.ResponseRecorder) (*models.DeleteDecisionResponse, int) {
	var response models.DeleteDecisionResponse

	require.NotNil(t, resp)
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	require.NoError(t, err)

	return &response, resp.Code
}

func readDecisionsStreamResp(t *testing.T, resp *httptest.ResponseRecorder) (map[string][]*models.Decision, int) {
	response := make(map[string][]*models.Decision)

	require.NotNil(t, resp)
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	require.NoError(t, err)

	return response, resp.Code
}

func CreateTestMachine(t *testing.T, ctx context.Context, router *gin.Engine, token string) string {
	regReq := MachineTest
	regReq.RegistrationToken = token
	b, err := json.Marshal(regReq)
	require.NoError(t, err)

	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	return body
}

func CreateTestBouncer(t *testing.T, ctx context.Context, config *csconfig.DatabaseCfg) (string, *database.Client) {
	dbClient, err := database.NewClient(ctx, config)
	require.NoError(t, err)

	apiKey, err := middlewares.GenerateAPIKey(keyLength)
	require.NoError(t, err)

	_, err = dbClient.CreateBouncer(ctx, "test", "127.0.0.1", middlewares.HashSHA512(apiKey), types.ApiKeyAuthType, false)
	require.NoError(t, err)

	return apiKey, dbClient
}

func TestWithWrongDBConfig(t *testing.T) {
	ctx := t.Context()
	config := LoadTestConfig(t)
	config.API.Server.DbConfig.Type = "test"
	apiServer, err := NewServer(ctx, config.API.Server)

	cstest.RequireErrorContains(t, err, "unable to init database client: unknown database type 'test'")
	assert.Nil(t, apiServer)
}

func TestWithWrongFlushConfig(t *testing.T) {
	ctx := t.Context()
	config := LoadTestConfig(t)
	maxItems := -1
	config.API.Server.DbConfig.Flush.MaxItems = &maxItems
	apiServer, err := NewServer(ctx, config.API.Server)

	cstest.RequireErrorContains(t, err, "max_items can't be zero or negative")
	assert.Nil(t, apiServer)
}

func TestUnknownPath(t *testing.T) {
	ctx := t.Context()
	router, _ := NewAPITest(t, ctx)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

/*

ListenURI              string              `yaml:"listen_uri,omitempty"` //127.0.0.1:8080
	TLS                    *TLSCfg             `yaml:"tls"`
	DbConfig               *DatabaseCfg        `yaml:"-"`
	LogDir                 string              `yaml:"-"`
	LogMedia               string              `yaml:"-"`
	OnlineClient           *OnlineApiClientCfg `yaml:"online_client"`
	ProfilesPath           string              `yaml:"profiles_path,omitempty"`
	Profiles               []*ProfileCfg       `yaml:"-"`
	LogLevel               *log.Level          `yaml:"log_level"`
	UseForwardedForHeaders bool                `yaml:"use_forwarded_for_headers,omitempty"`

*/

func TestLoggingDebugToFileConfig(t *testing.T) {
	ctx := t.Context()

	/*declare settings*/
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}

	tempDir, _ := os.MkdirTemp("", "crowdsec_tests")

	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: filepath.Join(tempDir, "ent"),
		Flush:  &flushConfig,
	}
	cfg := csconfig.LocalApiServerCfg{
		ListenURI: "127.0.0.1:8080",
		LogMedia:  "file",
		LogDir:    tempDir,
		DbConfig:  &dbconfig,
	}
	expectedFile := filepath.Join(tempDir, "crowdsec_api.log")
	expectedLines := []string{"/test42"}
	cfg.LogLevel = ptr.Of(log.DebugLevel)

	// Configure logging
	err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.LogFormat, cfg.CompressLogs, false)
	require.NoError(t, err)

	api, err := NewServer(ctx, &cfg)
	require.NoError(t, err)
	require.NotNil(t, api)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	// wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	// check file content
	data, err := os.ReadFile(expectedFile)
	require.NoError(t, err)

	for _, expectedStr := range expectedLines {
		assert.Contains(t, string(data), expectedStr)
	}
}

func TestLoggingErrorToFileConfig(t *testing.T) {
	ctx := t.Context()

	/*declare settings*/
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}

	tempDir, _ := os.MkdirTemp("", "crowdsec_tests")

	t.Cleanup(func() { os.RemoveAll(tempDir) })

	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: filepath.Join(tempDir, "ent"),
		Flush:  &flushConfig,
	}
	cfg := csconfig.LocalApiServerCfg{
		ListenURI: "127.0.0.1:8080",
		LogMedia:  "file",
		LogDir:    tempDir,
		DbConfig:  &dbconfig,
	}
	expectedFile := filepath.Join(tempDir, "crowdsec_api.log")
	cfg.LogLevel = ptr.Of(log.ErrorLevel)

	// Configure logging
	err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.LogFormat, cfg.CompressLogs, false)
	require.NoError(t, err)

	api, err := NewServer(ctx, &cfg)
	require.NoError(t, err)
	require.NotNil(t, api)

	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
	// wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	// check file content
	x, err := os.ReadFile(expectedFile)
	if err == nil {
		require.Empty(t, x)
	}

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)
}
