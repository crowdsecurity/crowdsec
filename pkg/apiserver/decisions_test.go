package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestDeleteDecisionRange(t *testing.T) {
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	InsertAlertFromFile("./tests/alert_minibulk.json", router, loginResp)

	// delete by ip wrong
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/v1/decisions?range=1.2.3.0/24", strings.NewReader(""))
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
	InsertAlertFromFile("./tests/alert_minibulk.json", router, loginResp)

	// delete by ip wrong
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/v1/decisions?ip=1.2.3.4", strings.NewReader(""))
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
	InsertAlertFromFile("./tests/alert_minibulk.json", router, loginResp)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Decision
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/decisions", strings.NewReader(""))
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
	InsertAlertFromFile("./tests/alert_sample.json", router, loginResp)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Decision
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/v1/decisions", strings.NewReader(""))
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
	InsertAlertFromFile("./tests/alert_sample.json", router, loginResp)

	// Delete alert with Invalid ID
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/v1/decisions/test", strings.NewReader(""))
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
	InsertAlertFromFile("./tests/alert_sample.json", router, loginResp)

	// Delete alert with Invalid filter
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("DELETE", "/v1/decisions?test=test", strings.NewReader(""))
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

func TestStreamStartDecisionDedup(t *testing.T) {
	//Ensure that at stream startup we only get the longest decision
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	InsertAlertFromFile("./tests/alert_sample.json", router, loginResp)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Stream, we only get one decision (the longest one)
	w, err := RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/3", loginResp, router)
	assert.Equal(t, 200, w.Code)

	// Get Stream, we only get one decision (the longest one, id=2)
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(2))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/2", loginResp, router)
	assert.Equal(t, 200, w.Code)

	// And get the remaining decision (1)
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(1))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// We delete the last decision, we receive the delete order
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/1", loginResp, router)
	assert.Equal(t, 200, w.Code)

	//and now we only get a deleted decision
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 1)
	assert.Equal(t, decisions["deleted"][0].ID, int64(1))
	assert.Equal(t, *decisions["deleted"][0].Origin, "test")
	assert.Equal(t, *decisions["deleted"][0].Value, "127.0.0.1")
	assert.Equal(t, len(decisions["new"]), 0)
}

func TestStreamDecisionDedup(t *testing.T) {
	//Ensure that at stream startup we only get the longest decision
	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	InsertAlertFromFile("./tests/alert_sample.json", router, loginResp)

	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Get Stream, we only get one decision (the longest one)
	w, err := RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	assert.Equal(t, err, nil)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/3", loginResp, router)
	assert.Equal(t, 200, w.Code)

	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream", APIKey, router)
	assert.Equal(t, err, nil)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 0)

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/2", loginResp, router)
	assert.Equal(t, 200, w.Code)

	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream", APIKey, router)
	assert.Equal(t, err, nil)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 0)

	// We delete the last decision, we receive the delete order
	w, err = RecordAgentResponse("DELETE", "/v1/decisions/1", loginResp, router)
	assert.Equal(t, 200, w.Code)

	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 1)
	assert.Equal(t, decisions["deleted"][0].ID, int64(1))
	assert.Equal(t, *decisions["deleted"][0].Origin, "test")
	assert.Equal(t, *decisions["deleted"][0].Value, "127.0.0.1")
	assert.Equal(t, len(decisions["new"]), 0)
}

func TestStreamDecisionFilters(t *testing.T) {

	router, loginResp, err := InitMachineTest()
	if err != nil {
		log.Fatalln(err.Error())
	}

	// Create Valid Alert
	InsertAlertFromFile("./tests/alert_stream_fixture.json", router, loginResp)
	APIKey, err := CreateTestBouncer()
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	w, err := RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true", APIKey, router)
	decisions, code, err := readDecisionsStreamResp(w)

	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 3)
	assert.Equal(t, decisions["new"][0].ID, int64(1))
	assert.Equal(t, *decisions["new"][0].Origin, "test1")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")
	assert.Equal(t, *decisions["new"][0].Scenario, "crowdsecurity/http_bf")
	assert.Equal(t, decisions["new"][1].ID, int64(2))
	assert.Equal(t, *decisions["new"][1].Origin, "test2")
	assert.Equal(t, *decisions["new"][1].Value, "127.0.0.1")
	assert.Equal(t, *decisions["new"][1].Scenario, "crowdsecurity/ssh_bf")
	assert.Equal(t, decisions["new"][2].ID, int64(3))
	assert.Equal(t, *decisions["new"][2].Origin, "test3")
	assert.Equal(t, *decisions["new"][2].Value, "127.0.0.1")
	assert.Equal(t, *decisions["new"][2].Scenario, "crowdsecurity/ddos")

	// test filter scenarios_not_containing
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=http", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 2)
	assert.Equal(t, decisions["new"][0].ID, int64(2))
	assert.Equal(t, decisions["new"][1].ID, int64(3))

	// test  filter scenarios_containing
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true&scenarios_containing=http", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(1))

	// test filters both by scenarios_not_containing and scenarios_containing
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh&scenarios_containing=ddos", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))

	// test filter by origin
	w, err = RecordBouncerResponse("GET", "/v1/decisions/stream?startup=true&origins=test1,test2", APIKey, router)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 2)
	assert.Equal(t, decisions["new"][0].ID, int64(1))
	assert.Equal(t, decisions["new"][1].ID, int64(2))
}
