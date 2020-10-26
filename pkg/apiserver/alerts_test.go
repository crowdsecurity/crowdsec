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
	req, _ := http.NewRequest("POST", "/v1/watchers/login", strings.NewReader(body))
	req.Header.Add("User-Agent", UserAgent)
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
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader("test"))
	req.Header.Add("User-Agent", UserAgent)
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
	req, _ = http.NewRequest("POST", "/v1/alerts", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
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
	req, _ = http.NewRequest("POST", "/v1/alerts", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "[\"1\"]", w.Body.String())
}

func TestAlertListFilters(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	alertContentBytes, err := ioutil.ReadFile("./tests/alert_ssh-bf.json")
	if err != nil {
		log.Fatal(err)
	}
	alertContent := string(alertContentBytes)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?test=test", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"Filter parameter 'test' is unknown (=test): invalid filter\"}", w.Body.String())

	//base
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	//check alert and decision
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test decision_type filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?decision_type=ban", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test decision_type filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?decision_type=ratata", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test scope
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?scope=Ip", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test scope
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?scope=rarara", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test scenario
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?scenario=crowdsecurity/ssh-bf", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test scenario
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?scenario=crowdsecurity/nope", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test ip
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?ip=91.121.79.195", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test ip
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?ip=99.122.77.195", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test ip
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?ip=gruueq", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, w.Body.String(), `{"message":"unable to parse 'gruueq': %!s(\u003cnil\u003e): invalid ip address / range"}`)

	//test range
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?range=91.121.79.0/24", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test range
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?range=99.122.77.0/24", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test range
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?range=ratata", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, w.Body.String(), `{"message":"unable to convert 'ratata' to int interval: 'ratata' is not a valid CIDR: invalid ip address / range"}`)

	//test since
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?since=1h", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test since
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?since=1ns", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test since
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?since=1zuzu", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, w.Body.String(), `{"message":"while parsing duration: time: unknown unit zuzu in duration 1zuzu"}`)

	//test until
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?until=1ns", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test until
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?until=1m", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test until
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?until=1zuzu", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, w.Body.String(), `{"message":"while parsing duration: time: unknown unit zuzu in duration 1zuzu"}`)

	//test simulated
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?simulated=true", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test simulated
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?simulated=false", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test has active decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?has_active_decision=true", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Ip 91.121.79.195 performed 'crowdsecurity/ssh-bf' (6 events over ")
	assert.Contains(t, w.Body.String(), `scope":"Ip","simulated":false,"start_ip":1534676931,"type":"ban","value":"91.121.79.195"`)

	//test has active decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?has_active_decision=false", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "null", w.Body.String())

	//test has active decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?has_active_decision=ratatqata", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, w.Body.String(), `{"message":"'ratatqata' is not a boolean: strconv.ParseBool: parsing \"ratatqata\": invalid syntax: unable to parse type"}`)

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
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// List Alert with invalid filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts?test=test", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)
	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"Filter parameter 'test' is unknown (=test): invalid filter\"}", w.Body.String())

	// List Alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/alerts", nil)
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "crowdsecurity/test")
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
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(alertContent))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	// Delete Alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/alerts", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	assert.Equal(t, 403, w.Code)
	assert.Equal(t, "{\"message\":\"access forbidden from this IP ()\"}", w.Body.String())
}
