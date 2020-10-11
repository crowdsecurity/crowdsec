package apiserver

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetDecision(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Decision with invalid filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/decisions?test=test", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"'test' doesn't exist: invalid filter\"}", w.Body.String())

	// Get Decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/decisions", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"end_ip\":2130706433,\"id\":1,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"ip\",\"start_ip\":2130706433,\"type\":\"ban\",\"value\":\"127.0.0.1\"}]")

	CleanDB()
}

func TestDeleteDecisionByID(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// Delete alert with Invalid ID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/decisions/test", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "{\"message\":\"decision_id must be valid integer\"}", w.Body.String())

	// Delete alert with ID that not exist
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/decisions/100", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"decision with id '100' doesn't exist: unable to delete\"}", w.Body.String())

	// Delete alert with valid ID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/decisions/1", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"nbDeleted\":\"1\"}", w.Body.String())

	CleanDB()
}

func TestDeleteDecision(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// Delete alert with Invalid filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/decisions?test=test", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"'test' doesn't exist: invalid filter\"}", w.Body.String())

	// Delete alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/decisions", strings.NewReader(""))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"nbDeleted\":\"1\"}", w.Body.String())

	CleanDB()
}

func TestStreamDecision(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_sample.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/alerts", strings.NewReader(alertContent))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Stream
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/decisions/stream", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"deleted\":null,\"new\":null}", w.Body.String())

	// Get Stream just startup
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/decisions/stream?startup=true", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"end_ip\":2130706433,\"id\":1,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"ip\",\"start_ip\":2130706433,\"type\":\"ban\",\"value\":\"127.0.0.1\"}]}")

	CleanDB()
}
