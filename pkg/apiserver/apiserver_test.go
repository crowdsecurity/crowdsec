package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
	"github.com/crowdsecurity/go-cs-lib/version"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var testMachineID = "test"
var testPassword = strfmt.Password("test")
var MachineTest = models.WatcherAuthRequest{
	MachineID: &testMachineID,
	Password:  &testPassword,
}

var UserAgent = fmt.Sprintf("crowdsec-test/%s", version.Version)
var emptyBody = strings.NewReader("")

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
		DbConfig:     &dbconfig,
		ProfilesPath: "./tests/profiles.yaml",
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
	if err := config.API.Server.LoadProfiles(); err != nil {
		log.Fatalf("failed to load profiles: %s", err)
	}

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
	if err := config.API.Server.LoadProfiles(); err != nil {
		log.Fatalf("failed to load profiles: %s", err)
	}

	return config
}

func NewAPIServer(t *testing.T) (*APIServer, csconfig.Config, error) {
	config := LoadTestConfig(t)

	os.Remove("./ent")
	apiServer, err := NewServer(config.API.Server)
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}

	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)

	return apiServer, config, nil
}

func NewAPITest(t *testing.T) (*gin.Engine, csconfig.Config, error) {
	apiServer, config, err := NewAPIServer(t)
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}
	err = apiServer.InitController()
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}
	router, err := apiServer.Router()
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}

	return router, config, nil
}

func NewAPITestForwardedFor(t *testing.T) (*gin.Engine, csconfig.Config, error) {
	config := LoadTestConfigForwardedFor(t)

	os.Remove("./ent")
	apiServer, err := NewServer(config.API.Server)
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}
	err = apiServer.InitController()
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}

	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)
	router, err := apiServer.Router()
	if err != nil {
		return nil, config, fmt.Errorf("unable to run local API: %s", err)
	}

	return router, config, nil
}

func ValidateMachine(machineID string, config *csconfig.DatabaseCfg) error {
	dbClient, err := database.NewClient(config)
	if err != nil {
		return fmt.Errorf("unable to create new database client: %s", err)
	}

	if err := dbClient.ValidateMachine(machineID); err != nil {
		return fmt.Errorf("unable to validate machine: %s", err)
	}

	return nil
}

func GetMachineIP(machineID string, config *csconfig.DatabaseCfg) (string, error) {
	dbClient, err := database.NewClient(config)
	if err != nil {
		return "", fmt.Errorf("unable to create new database client: %s", err)
	}
	machines, err := dbClient.ListMachines()
	if err != nil {
		return "", fmt.Errorf("Unable to list machines: %s", err)
	}

	for _, machine := range machines {
		if machine.MachineId == machineID {
			return machine.IpAddress, nil
		}
	}

	return "", nil
}

func GetAlertReaderFromFile(path string) *strings.Reader {
	alertContentBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	alerts := make([]*models.Alert, 0)
	if err = json.Unmarshal(alertContentBytes, &alerts); err != nil {
		log.Fatal(err)
	}

	for _, alert := range alerts {
		*alert.StartAt = time.Now().UTC().Format(time.RFC3339)
		*alert.StopAt = time.Now().UTC().Format(time.RFC3339)
	}

	alertContent, err := json.Marshal(alerts)
	if err != nil {
		log.Fatal(err)
	}

	return strings.NewReader(string(alertContent))
}

func readDecisionsGetResp(resp *httptest.ResponseRecorder) ([]*models.Decision, int, error) {
	var response []*models.Decision

	if resp == nil {
		return nil, 0, errors.New("response is nil")
	}
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	if err != nil {
		return nil, resp.Code, err
	}

	return response, resp.Code, nil
}

func readDecisionsErrorResp(resp *httptest.ResponseRecorder) (map[string]string, int, error) {
	var response map[string]string

	if resp == nil {
		return nil, 0, errors.New("response is nil")
	}
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	if err != nil {
		return nil, resp.Code, err
	}

	return response, resp.Code, nil
}

func readDecisionsDeleteResp(resp *httptest.ResponseRecorder) (*models.DeleteDecisionResponse, int, error) {
	var response models.DeleteDecisionResponse

	if resp == nil {
		return nil, 0, errors.New("response is nil")
	}
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	if err != nil {
		return nil, resp.Code, err
	}

	return &response, resp.Code, nil
}

func readDecisionsStreamResp(resp *httptest.ResponseRecorder) (map[string][]*models.Decision, int, error) {
	response := make(map[string][]*models.Decision)

	if resp == nil {
		return nil, 0, errors.New("response is nil")
	}
	err := json.Unmarshal(resp.Body.Bytes(), &response)
	if err != nil {
		return nil, resp.Code, err
	}

	return response, resp.Code, nil
}

func CreateTestMachine(router *gin.Engine) (string, error) {
	b, err := json.Marshal(MachineTest)
	if err != nil {
		return "", fmt.Errorf("unable to marshal MachineTest")
	}
	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/v1/watchers", strings.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	return body, nil
}

func CreateTestBouncer(config *csconfig.DatabaseCfg) (string, error) {
	dbClient, err := database.NewClient(config)
	if err != nil {
		log.Fatalf("unable to create new database client: %s", err)
	}

	apiKey, err := middlewares.GenerateAPIKey(keyLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate api key: %s", err)
	}

	_, err = dbClient.CreateBouncer("test", "127.0.0.1", middlewares.HashSHA512(apiKey), types.ApiKeyAuthType)
	if err != nil {
		return "", fmt.Errorf("unable to create blocker: %s", err)
	}

	return apiKey, nil
}

func TestWithWrongDBConfig(t *testing.T) {
	config := LoadTestConfig(t)
	config.API.Server.DbConfig.Type = "test"
	apiServer, err := NewServer(config.API.Server)

	cstest.RequireErrorContains(t, err, "unable to init database client: unknown database type 'test'")
	assert.Nil(t, apiServer)
}

func TestWithWrongFlushConfig(t *testing.T) {
	config := LoadTestConfig(t)
	maxItems := -1
	config.API.Server.DbConfig.Flush.MaxItems = &maxItems
	apiServer, err := NewServer(config.API.Server)

	cstest.RequireErrorContains(t, err, "max_items can't be zero or negative number")
	assert.Nil(t, apiServer)
}

func TestUnknownPath(t *testing.T) {
	router, _, err := NewAPITest(t)
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("User-Agent", UserAgent)
	router.ServeHTTP(w, req)

	assert.Equal(t, 404, w.Code)
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
	lvl := log.DebugLevel
	expectedFile := fmt.Sprintf("%s/crowdsec_api.log", tempDir)
	expectedLines := []string{"/test42"}
	cfg.LogLevel = &lvl

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.CompressLogs, false); err != nil {
		t.Fatal(err)
	}

	api, err := NewServer(&cfg)
	if err != nil {
		t.Fatalf("failed to create api : %s", err)
	}

	if api == nil {
		t.Fatalf("failed to create api #2 is nbill")
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, 404, w.Code)
	//wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	//check file content
	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("failed to read file : %s", err)
	}

	for _, expectedStr := range expectedLines {
		if !strings.Contains(string(data), expectedStr) {
			t.Fatalf("expected %s in %s", expectedStr, string(data))
		}
	}
}

func TestLoggingErrorToFileConfig(t *testing.T) {
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
	lvl := log.ErrorLevel
	expectedFile := fmt.Sprintf("%s/crowdsec_api.log", tempDir)
	cfg.LogLevel = &lvl

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel, cfg.LogMaxSize, cfg.LogMaxFiles, cfg.LogMaxAge, cfg.CompressLogs, false); err != nil {
		t.Fatal(err)
	}
	api, err := NewServer(&cfg)
	if err != nil {
		t.Fatalf("failed to create api : %s", err)
	}

	if api == nil {
		t.Fatalf("failed to create api #2 is nbill")
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, 404, w.Code)
	//wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	//check file content
	x, err := os.ReadFile(expectedFile)
	if err == nil && len(x) > 0 {
		t.Fatalf("file should be empty, got '%s'", x)
	}

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)
}
