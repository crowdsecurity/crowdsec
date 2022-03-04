package apiserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDeleteDecisionRange(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_minibulk.json")
	if err != nil {
		log.Fatal(err)
	}
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	// delete by ip wrong
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?range=1.2.3.0/24", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by range
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?range=91.121.79.0/24&contains=false", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"2"}`, w.Body.String())

	// delete by range : ensure it was already deleted
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?range=91.121.79.0/24", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())
}

func TestDeleteDecisionFilter(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_minibulk.json")
	if err != nil {
		log.Fatal(err)
	}
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	// delete by ip wrong
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?ip=1.2.3.4", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by ip good
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?ip=91.121.79.179", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())

	// delete by scope/value
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?scopes=Ip&value=91.121.79.178", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestGetDecisionFilters(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_minibulk.json")
	if err != nil {
		log.Fatal(err)
	}
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	assert.Contains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : type filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions?type=ban", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	assert.Contains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : scope/value
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions?scopes=Ip&value=91.121.79.179", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : ip filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions?ip=91.121.79.179", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get decision : by range
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions?range=91.121.79.0/24&contains=false", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	assert.Contains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)
}

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
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Decision
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"}]")

	// Get Decision with invalid filter. It should ignore this filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions?test=test", strings.NewReader(""))
	req.Header.Add("User-Agent", UserAgent)
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"}]")

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
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	// Delete alert with Invalid ID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions/test", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	assert.Equal(t, 400, w.Code)
	assert.Equal(t, "{\"message\":\"decision_id must be valid integer\"}", w.Body.String())

	// Delete alert with ID that not exist
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions/100", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"decision with id '100' doesn't exist: unable to delete\"}", w.Body.String())

	// Delete alert with valid ID
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions/1", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"nbDeleted\":\"1\"}", w.Body.String())

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
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	// Delete alert with Invalid filter
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions?test=test", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	assert.Equal(t, 500, w.Code)
	assert.Equal(t, "{\"message\":\"'test' doesn't exist: invalid filter\"}", w.Body.String())

	// Delete alert
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/v1/decisions", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"nbDeleted\":\"3\"}", w.Body.String())

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
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Stream
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"deleted\":null,\"new\":null}", w.Body.String())

	// Get Stream just startup
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	// the decision with id=3 is only returned because it's the longest decision
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"}]}")
	assert.NotContains(t, w.Body.String(), "\"id\":2")
	assert.NotContains(t, w.Body.String(), "\"id\":1")
	assert.Contains(t, w.Body.String(), "2h")

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions
	// targetting same IP
	req, _ = http.NewRequest("DELETE", "/v1/decisions/3", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
	assert.Equal(t, 200, w.Code)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	// the decision with id=2 is only returned because it's the longest decision
	assert.Contains(t, w.Body.String(), "\"id\":2,\"origin\":\"test\",\"scenario\":\"crowdsecurity/test\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"}]}")
	assert.NotContains(t, w.Body.String(), "\"id\":3")
	assert.NotContains(t, w.Body.String(), "\"id\":1")
	assert.Contains(t, w.Body.String(), "1h")
	assert.Contains(t, w.Body.String(), "\"deleted\":null")

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	req, _ = http.NewRequest("DELETE", "/v1/decisions/2", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "{\"deleted\":null,\"new\":null}", w.Body.String())

	// Now all decisions for this IP are deleted, we should receive it in stream
	req, _ = http.NewRequest("DELETE", "/v1/decisions/1", strings.NewReader(""))
	AddAuthHeaders(req, loginResp)
	router.ServeHTTP(w, req)
}
func TestStreamDecisionFilters(t *testing.T) {

	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	alertContentBytes, err := ioutil.ReadFile("./tests/alert_stream_fixture.json")
	if err != nil {
		log.Fatal(err)
	}
	alerts := make([]*models.Alert, 0)
	if err := json.Unmarshal(alertContentBytes, &alerts); err != nil {
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
	w := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/v1/alerts", strings.NewReader(string(alertContent)))
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", loginResp.Token))
	router.ServeHTTP(w, req)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":1,\"origin\":\"test1\",\"scenario\":\"crowdsecurity/http_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":2,\"origin\":\"test2\",\"scenario\":\"crowdsecurity/ssh_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test3\",\"scenario\":\"crowdsecurity/ddos\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")

	// test filter scenarios_not_containing
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=http", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotContains(t, w.Body.String(), "\"id\":1,\"origin\":\"test1\",\"scenario\":\"crowdsecurity/http_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":2,\"origin\":\"test2\",\"scenario\":\"crowdsecurity/ssh_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test3\",\"scenario\":\"crowdsecurity/ddos\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")

	// test  filter scenarios_containing
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true&scenarios_containing=http", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":1,\"origin\":\"test1\",\"scenario\":\"crowdsecurity/http_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.NotContains(t, w.Body.String(), "\"id\":2,\"origin\":\"test2\",\"scenario\":\"crowdsecurity/ssh_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.NotContains(t, w.Body.String(), "\"id\":3,\"origin\":\"test3\",\"scenario\":\"crowdsecurity/ddos\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")

	// test filters both by scenarios_not_containing and scenarios_containing
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh&scenarios_containing=ddos", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.NotContains(t, w.Body.String(), "\"id\":1,\"origin\":\"test1\",\"scenario\":\"crowdsecurity/http_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.NotContains(t, w.Body.String(), "\"id\":2,\"origin\":\"test2\",\"scenario\":\"crowdsecurity/ssh_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":3,\"origin\":\"test3\",\"scenario\":\"crowdsecurity/ddos\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")

	// test filter by origin
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/v1/decisions/stream?startup=true&origins=test1,test2", strings.NewReader(""))
	req.Header.Add("X-Api-Key", APIKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "\"id\":1,\"origin\":\"test1\",\"scenario\":\"crowdsecurity/http_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.Contains(t, w.Body.String(), "\"id\":2,\"origin\":\"test2\",\"scenario\":\"crowdsecurity/ssh_bf\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
	assert.NotContains(t, w.Body.String(), "\"id\":3,\"origin\":\"test3\",\"scenario\":\"crowdsecurity/ddos\",\"scope\":\"Ip\",\"type\":\"ban\",\"value\":\"127.0.0.1\"")
}
