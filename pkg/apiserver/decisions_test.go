package apiserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	APIKEY   = "apikey"
	PASSWORD = "password"
)

func TestDeleteDecisionRange(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// delete by ip wrong
	w := lapi.RecordResponse("DELETE", "/v1/decisions?range=1.2.3.0/24", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by range

	w = lapi.RecordResponse("DELETE", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"2"}`, w.Body.String())

	// delete by range : ensure it was already deleted

	w = lapi.RecordResponse("DELETE", "/v1/decisions?range=91.121.79.0/24", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())
}

func TestDeleteDecisionFilter(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// delete by ip wrong

	w := lapi.RecordResponse("DELETE", "/v1/decisions?ip=1.2.3.4", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by ip good

	w = lapi.RecordResponse("DELETE", "/v1/decisions?ip=91.121.79.179", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())

	// delete by scope/value

	w = lapi.RecordResponse("DELETE", "/v1/decisions?scopes=Ip&value=91.121.79.178", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestDeleteDecisionFilterByScenario(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// delete by wrong scenario

	w := lapi.RecordResponse("DELETE", "/v1/decisions?scenario=crowdsecurity/ssh-bff", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by scenario good

	w = lapi.RecordResponse("DELETE", "/v1/decisions?scenario=crowdsecurity/ssh-bf", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"2"}`, w.Body.String())
}

func TestGetDecisionFilters(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// Get Decision

	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err := readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 2)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[1].Scenario)
	assert.Equal(t, "91.121.79.178", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	// Get Decision : type filter

	w = lapi.RecordResponse("GET", "/v1/decisions?type=ban", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 2)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[1].Scenario)
	assert.Equal(t, "91.121.79.178", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.Contains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : scope/value

	w = lapi.RecordResponse("GET", "/v1/decisions?scopes=Ip&value=91.121.79.179", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 1)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : ip filter

	w = lapi.RecordResponse("GET", "/v1/decisions?ip=91.121.79.179", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 1)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get decision : by range
	w = lapi.RecordResponse("GET", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 2)
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.179")
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.178")
}

func TestGetDecision(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Decision
	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code, err := readDecisionsGetResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 3)
	/*decisions get doesn't perform deduplication*/
	assert.Equal(t, "crowdsecurity/test", *decisions[0].Scenario)
	assert.Equal(t, "127.0.0.1", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	assert.Equal(t, "crowdsecurity/test", *decisions[1].Scenario)
	assert.Equal(t, "127.0.0.1", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	assert.Equal(t, "crowdsecurity/test", *decisions[2].Scenario)
	assert.Equal(t, "127.0.0.1", *decisions[2].Value)
	assert.Equal(t, int64(3), decisions[2].ID)

	// Get Decision with invalid filter. It should ignore this filter
	w = lapi.RecordResponse("GET", "/v1/decisions?test=test", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	assert.Len(t, decisions, 3)
}

func TestDeleteDecisionByID(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	//Have one alerts
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err := readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)

	// Delete alert with Invalid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/test", emptyBody, PASSWORD)
	assert.Equal(t, 400, w.Code)
	errResp, _, err := readDecisionsErrorResp(w)
	require.NoError(t, err)
	assert.Equal(t, "decision_id must be valid integer", errResp["message"])

	// Delete alert with ID that not exist
	w = lapi.RecordResponse("DELETE", "/v1/decisions/100", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	errResp, _, err = readDecisionsErrorResp(w)
	require.NoError(t, err)
	assert.Equal(t, "decision with id '100' doesn't exist: unable to delete", errResp["message"])

	//Have one alerts
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)

	// Delete alert with valid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	require.NoError(t, err)
	assert.Equal(t, "1", resp.NbDeleted)

	//Have one alert (because we delete an alert that has dup targets)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
}

func TestDeleteDecision(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Delete alert with Invalid filter
	w := lapi.RecordResponse("DELETE", "/v1/decisions?test=test", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	errResp, _, err := readDecisionsErrorResp(w)
	require.NoError(t, err)
	assert.Equal(t, "'test' doesn't exist: invalid filter", errResp["message"])

	// Delete all alert
	w = lapi.RecordResponse("DELETE", "/v1/decisions", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	require.NoError(t, err)
	assert.Equal(t, "3", resp.NbDeleted)
}

func TestStreamStartDecisionDedup(t *testing.T) {
	//Ensure that at stream startup we only get the longest decision
	lapi := SetupLAPITest(t)

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Stream, we only get one decision (the longest one)
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err := readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(3), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w = lapi.RecordResponse("DELETE", "/v1/decisions/3", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// Get Stream, we only get one decision (the longest one, id=2)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(2), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w = lapi.RecordResponse("DELETE", "/v1/decisions/2", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// And get the remaining decision (1)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(1), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete the last decision, we receive the delete order
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	//and now we only get a deleted decision
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	require.NoError(t, err)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions["deleted"], 1)
	assert.Equal(t, int64(1), decisions["deleted"][0].ID)
	assert.Equal(t, "test", *decisions["deleted"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["deleted"][0].Value)
	assert.Empty(t, decisions["new"])
}

type DecisionCheck struct {
	ID       int64
	Origin   string
	Scenario string
	Value    string
	Duration string
	Type     string
}

type DecisionTest struct {
	TestName      string
	Method        string
	Route         string
	CheckCodeOnly bool
	Code          int
	LenNew        int
	LenDeleted    int
	NewChecks     []DecisionCheck
	DelChecks     []DecisionCheck
	AuthType      string
}
