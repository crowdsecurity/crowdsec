package apiserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeleteDecisionRange(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// delete by ip wrong
	w := lapi.RecordResponse("DELETE", "/v1/decisions?range=1.2.3.0/24", emptyBody)
	assert.Equal(t, 200, w.Code)

	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by range

	w = lapi.RecordResponse("DELETE", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"2"}`, w.Body.String())

	// delete by range : ensure it was already deleted

	w = lapi.RecordResponse("DELETE", "/v1/decisions?range=91.121.79.0/24", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())
}

func TestDeleteDecisionFilter(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// delete by ip wrong

	w := lapi.RecordResponse("DELETE", "/v1/decisions?ip=1.2.3.4", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by ip good

	w = lapi.RecordResponse("DELETE", "/v1/decisions?ip=91.121.79.179", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())

	// delete by scope/value

	w = lapi.RecordResponse("DELETE", "/v1/decisions?scopes=Ip&value=91.121.79.178", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestGetDecisionFilters(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// Get Decision

	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err := readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 2, len(decisions))
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[1].Scenario)
	assert.Equal(t, "91.121.79.178", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	// Get Decision : type filter

	w = lapi.RecordResponse("GET", "/v1/decisions?type=ban", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 2, len(decisions))
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[1].Scenario)
	assert.Equal(t, "91.121.79.178", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.Contains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : scope/value

	w = lapi.RecordResponse("GET", "/v1/decisions?scopes=Ip&value=91.121.79.179", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 1, len(decisions))
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : ip filter

	w = lapi.RecordResponse("GET", "/v1/decisions?ip=91.121.79.179", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 1, len(decisions))
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get decision : by range
	w = lapi.RecordResponse("GET", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err = readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 2, len(decisions))
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.179")
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.178")

}

func TestGetDecision(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Decision
	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody)
	assert.Equal(t, 200, w.Code)
	decisions, code, err := readDecisionsGetResp(w)
	assert.Nil(t, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 3, len(decisions))
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
	w = lapi.RecordResponse("GET", "/v1/decisions?test=test", emptyBody)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 3, len(decisions))
}

func TestDeleteDecisionByID(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	//Have one alerts
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)

	// Delete alert with Invalid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/test", emptyBody)
	assert.Equal(t, 400, w.Code)
	err_resp, _, err := readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, err_resp["message"], "decision_id must be valid integer")

	// Delete alert with ID that not exist
	w = lapi.RecordResponse("DELETE", "/v1/decisions/100", emptyBody)
	assert.Equal(t, 500, w.Code)
	err_resp, _, err = readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, err_resp["message"], "decision with id '100' doesn't exist: unable to delete")

	//Have one alerts
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)

	// Delete alert with valid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	assert.NoError(t, err)
	assert.Equal(t, resp.NbDeleted, "1")

	//Have one alert (because we delete an alert that has dup targets)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
}

func TestDeleteDecision(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Delete alert with Invalid filter
	w := lapi.RecordResponse("DELETE", "/v1/decisions?test=test", emptyBody)
	assert.Equal(t, 500, w.Code)
	err_resp, _, err := readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, err_resp["message"], "'test' doesn't exist: invalid filter")

	// Delete all alert
	w = lapi.RecordResponse("DELETE", "/v1/decisions", emptyBody)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	assert.Equal(t, resp.NbDeleted, "3")
}

func TestStreamStartDecisionDedup(t *testing.T) {
	//Ensure that at stream startup we only get the longest decision
	lapi := SetupLAPITest(t)

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Stream, we only get one decision (the longest one)
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w = lapi.RecordResponse("DELETE", "/v1/decisions/3", emptyBody)
	assert.Equal(t, 200, w.Code)

	// Get Stream, we only get one decision (the longest one, id=2)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(2))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w = lapi.RecordResponse("DELETE", "/v1/decisions/2", emptyBody)
	assert.Equal(t, 200, w.Code)

	// And get the remaining decision (1)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(1))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// We delete the last decision, we receive the delete order
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody)
	assert.Equal(t, 200, w.Code)

	//and now we only get a deleted decision
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
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
	lapi := SetupLAPITest(t)

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Stream, we only get one decision (the longest one)
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))
	assert.Equal(t, *decisions["new"][0].Origin, "test")
	assert.Equal(t, *decisions["new"][0].Value, "127.0.0.1")

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w = lapi.RecordResponse("DELETE", "/v1/decisions/3", emptyBody)
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse("GET", "/v1/decisions/stream", emptyBody)
	assert.Equal(t, err, nil)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 0)

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w = lapi.RecordResponse("DELETE", "/v1/decisions/2", emptyBody)
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse("GET", "/v1/decisions/stream", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, code, 200)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 0)

	// We delete the last decision, we receive the delete order
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody)
	assert.Equal(t, 200, w.Code)

	w = lapi.RecordResponse("GET", "/v1/decisions/stream", emptyBody)
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

	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_stream_fixture.json")

	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody)
	decisions, code, err := readDecisionsStreamResp(w)

	assert.Equal(t, 200, code)
	assert.Equal(t, err, nil)
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
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=http", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 2)
	assert.Equal(t, decisions["new"][0].ID, int64(2))
	assert.Equal(t, decisions["new"][1].ID, int64(3))

	// test  filter scenarios_containing
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true&scenarios_containing=http", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(1))

	// test filters both by scenarios_not_containing and scenarios_containing
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh&scenarios_containing=ddos", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 1)
	assert.Equal(t, decisions["new"][0].ID, int64(3))

	// test filter by origin
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true&origins=test1,test2", emptyBody)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, len(decisions["deleted"]), 0)
	assert.Equal(t, len(decisions["new"]), 2)
	assert.Equal(t, decisions["new"][0].ID, int64(1))
	assert.Equal(t, decisions["new"][1].ID, int64(2))
}
