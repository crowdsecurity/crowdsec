package apiserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/go-openapi/strfmt"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var testMachineID = "test"
var testPassword = strfmt.Password("test")
var MachineTest = models.WatcherAuthRequest{
	MachineID: &testMachineID,
	Password:  &testPassword,
}

var UserAgent = fmt.Sprintf("crowdsec-test/%s", cwversion.Version)

func LoadTestConfig() csconfig.Config {
	config := csconfig.Config{}
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}
	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: "./ent",
		Flush:  &flushConfig,
	}
	apiServerConfig := csconfig.LocalApiServerCfg{
		ListenURI:    "http://127.0.0.1:8080",
		DbConfig:     &dbconfig,
		ProfilesPath: "./tests/profiles.yaml",
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

func LoadTestConfigForwardedFor() csconfig.Config {
	config := csconfig.Config{}
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}
	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: "./ent",
		Flush:  &flushConfig,
	}
	apiServerConfig := csconfig.LocalApiServerCfg{
		ListenURI:              "http://127.0.0.1:8080",
		DbConfig:               &dbconfig,
		ProfilesPath:           "./tests/profiles.yaml",
		UseForwardedForHeaders: true,
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

func NewAPIServer() (*APIServer, error) {
	config := LoadTestConfig()
	os.Remove("./ent")
	apiServer, err := NewServer(config.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)
	return apiServer, nil
}

func NewAPITest() (*gin.Engine, error) {
	apiServer, err := NewAPIServer()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
	router, err := apiServer.Router()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
	return router, nil
}

func NewAPITestForwardedFor() (*gin.Engine, error) {
	config := LoadTestConfigForwardedFor()

	os.Remove("./ent")
	apiServer, err := NewServer(config.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
	log.Printf("Creating new API server")
	gin.SetMode(gin.TestMode)
	router, err := apiServer.Router()
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
	return router, nil
}

func ValidateMachine(machineID string) error {
	config := LoadTestConfig()
	dbClient, err := database.NewClient(config.API.Server.DbConfig)
	if err != nil {
		return fmt.Errorf("unable to create new database client: %s", err)
	}
	if err := dbClient.ValidateMachine(machineID); err != nil {
		return fmt.Errorf("unable to validate machine: %s", err)
	}
	return nil
}

func GetMachineIP(machineID string) (string, error) {
	config := LoadTestConfig()
	dbClient, err := database.NewClient(config.API.Server.DbConfig)
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

func CreateTestMachine(router *gin.Engine) (string, error) {
	b, err := json.Marshal(MachineTest)
	if err != nil {
		return "", fmt.Errorf("unable to marshal MachineTest")
	}
	body := string(b)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/watchers", strings.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	router.ServeHTTP(w, req)
	return body, nil
}

func CreateTestBouncer() (string, error) {
	config := LoadTestConfig()

	dbClient, err := database.NewClient(config.API.Server.DbConfig)
	if err != nil {
		log.Fatalf("unable to create new database client: %s", err)
	}
	apiKey, err := middlewares.GenerateAPIKey(keyLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate api key: %s", err)
	}
	err = dbClient.CreateBouncer("test", "127.0.0.1", middlewares.HashSHA512(apiKey))
	if err != nil {
		return "", fmt.Errorf("unable to create blocker: %s", err)
	}

	return apiKey, nil
}

func TestWithWrongDBConfig(t *testing.T) {
	config := LoadTestConfig()
	config.API.Server.DbConfig.Type = "test"
	apiServer, err := NewServer(config.API.Server)

	assert.Equal(t, apiServer, &APIServer{})
	assert.Equal(t, "unable to init database client: unknown database type", err.Error())
}

func TestWithWrongFlushConfig(t *testing.T) {
	config := LoadTestConfig()
	maxItems := -1
	config.API.Server.DbConfig.Flush.MaxItems = &maxItems
	apiServer, err := NewServer(config.API.Server)

	assert.Equal(t, apiServer, &APIServer{})
	assert.Equal(t, "max_items can't be zero or negative number", err.Error())
}

func TestUnknownPath(t *testing.T) {
	router, err := NewAPITest()
	if err != nil {
		log.Fatalf("unable to run local API: %s", err)
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
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
	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: "./ent",
		Flush:  &flushConfig,
	}
	cfg := csconfig.LocalApiServerCfg{
		ListenURI: "127.0.0.1:8080",
		LogMedia:  "file",
		LogDir:    ".",
		DbConfig:  &dbconfig,
	}
	lvl := log.DebugLevel
	expectedFile := "./crowdsec_api.log"
	expectedLines := []string{"/test42"}
	cfg.LogLevel = &lvl

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel); err != nil {
		t.Fatal(err.Error())
	}
	api, err := NewServer(&cfg)
	if err != nil {
		t.Fatalf("failed to create api : %s", err)
	}
	if api == nil {
		t.Fatalf("failed to create api #2 is nbill")
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, 404, w.Code)
	//wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	//check file content
	data, err := ioutil.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("failed to read file : %s", err)
	}

	for _, expectedStr := range expectedLines {
		if !strings.Contains(string(data), expectedStr) {
			t.Fatalf("expected %s in %s", expectedStr, string(data))
		}
	}

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)

}

func TestLoggingErrorToFileConfig(t *testing.T) {

	/*declare settings*/
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}
	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: "./ent",
		Flush:  &flushConfig,
	}
	cfg := csconfig.LocalApiServerCfg{
		ListenURI: "127.0.0.1:8080",
		LogMedia:  "file",
		LogDir:    ".",
		DbConfig:  &dbconfig,
	}
	lvl := log.ErrorLevel
	expectedFile := "./crowdsec_api.log"
	cfg.LogLevel = &lvl

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)

	// Configure logging
	if err := types.SetDefaultLoggerConfig(cfg.LogMedia, cfg.LogDir, *cfg.LogLevel); err != nil {
		t.Fatal(err.Error())
	}
	api, err := NewServer(&cfg)
	if err != nil {
		t.Fatalf("failed to create api : %s", err)
	}
	if api == nil {
		t.Fatalf("failed to create api #2 is nbill")
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test42", nil)
	req.Header.Set("User-Agent", UserAgent)
	api.router.ServeHTTP(w, req)
	assert.Equal(t, 404, w.Code)
	//wait for the request to happen
	time.Sleep(500 * time.Millisecond)

	//check file content
	_, err = ioutil.ReadFile(expectedFile)
	if err == nil {
		t.Fatalf("file should be empty")
	}

	os.Remove("./crowdsec.log")
	os.Remove(expectedFile)

}
