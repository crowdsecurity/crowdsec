package apiserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gin-gonic/gin"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func InitMachineTest() (*gin.Engine, models.WatcherAuthResponse, error) {
	router, err := NewAPITest()
	if err != nil {
		return nil, models.WatcherAuthResponse{}, fmt.Errorf("unable to run local API: %s", err)
	}

	body, err := CreateTestMachine(router)
	if err != nil {
		return nil, models.WatcherAuthResponse{}, fmt.Errorf("%s", err.Error())
	}

	err = ValidateMachine("test")
	if err != nil {
		log.Fatalln(err.Error())
	}

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/watchers/login", strings.NewReader(body))
	router.ServeHTTP(w, req)

	loginResp := models.WatcherAuthResponse{}
	err = json.NewDecoder(w.Body).Decode(&loginResp)
	if err != nil {
		log.Fatalln(err.Error())
	}

	return router, loginResp, nil
}

func TestCreateAlert(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Alert with invalid format
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader("test"))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "{\"message\":\"invalid character 'e' in literal true (expecting 'r')\"}", w.Body.String())

	// Create Alert with invalid input
	alertContentBytes, err := ioutil.ReadFile("./tests/invalidAlert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"validation failure list:\\nscenario in body is required\\nscenario_hash in body is required\\nscenario_version in body is required\\nsimulated in body is required\\nsource in body is required\"}", w.Body.String())

	// Create Valid Alert
	alertContentBytes, err = ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent = string(alertContentBytes)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "[\"1\"]", w.Body.String())

	CleanDB()
}

func TestListAlert(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// List Alert with invalid filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/alerts?test=test", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"'test' is unknown: %!s(\\u003cnil\\u003e): invalid filter\"}", w.Body.String())

	// List Alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "crowdsecurity/test")

	CleanDB()
}

func TestDeleteAlert(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// Delete Alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/alerts", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"message\":\"1 deleted alerts\"}", w.Body.String())

	CleanDB()
}
