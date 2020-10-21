package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	middlewares "github.com/crowdsecurity/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
	"github.com/crowdsecurity/crowdsec/pkg/models"
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

func CleanDB() {
	err := os.Remove("./crowdsec.db")
	if err != nil {
		log.Fatalf("unable to delete DB : %s", err)
	}
}

func LoadTestConfig() csconfig.GlobalConfig {
	config := csconfig.GlobalConfig{}
	maxAge := "1h"
	flushConfig := csconfig.FlushDBCfg{
		MaxAge: &maxAge,
	}
	dbconfig := csconfig.DatabaseCfg{
		Type:   "sqlite",
		DbPath: "./crowdsec.db",
		Flush:  &flushConfig,
	}
	apiServerConfig := csconfig.LocalApiServerCfg{
		ListenURI: "http://127.0.0.1:8080",
		DbConfig:  &dbconfig,
	}
	apiConfig := csconfig.APICfg{
		Server: &apiServerConfig,
	}
	config.API = &apiConfig
	return config
}

func NewAPITest() (*gin.Engine, error) {
	config := LoadTestConfig()
	apiServer, err := NewServer(config.API.Server)
	if err != nil {
		return nil, fmt.Errorf("unable to run local API: %s", err)
	}
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
	assert.Equal(t, "{\"message\":\"Page or Method not found\"}", w.Body.String())

	CleanDB()
}
