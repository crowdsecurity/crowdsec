package apiserver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestGetDecisionFilters(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_minibulk.json")

	// Get Decision

	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody, APIKEY)
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

	w = lapi.RecordResponse("GET", "/v1/decisions?type=ban", emptyBody, APIKEY)
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

	w = lapi.RecordResponse("GET", "/v1/decisions?scopes=Ip&value=91.121.79.179", emptyBody, APIKEY)
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

	w = lapi.RecordResponse("GET", "/v1/decisions?ip=91.121.79.179", emptyBody, APIKEY)
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
	w = lapi.RecordResponse("GET", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody, APIKEY)
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
	w := lapi.RecordResponse("GET", "/v1/decisions", emptyBody, APIKEY)
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
	w = lapi.RecordResponse("GET", "/v1/decisions?test=test", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, 3, len(decisions))
}

func TestDeleteDecisionByID(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	//Have one alerts
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))

	// Delete alert with Invalid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/test", emptyBody, PASSWORD)
	assert.Equal(t, 400, w.Code)
	err_resp, _, err := readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, "decision_id must be valid integer", err_resp["message"])

	// Delete alert with ID that not exist
	w = lapi.RecordResponse("DELETE", "/v1/decisions/100", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	err_resp, _, err = readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, "decision with id '100' doesn't exist: unable to delete", err_resp["message"])

	//Have one alerts
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))

	// Delete alert with valid ID
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	assert.NoError(t, err)
	assert.Equal(t, resp.NbDeleted, "1")

	//Have one alert (because we delete an alert that has dup targets)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, err, nil)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))
}

func TestDeleteDecision(t *testing.T) {
	lapi := SetupLAPITest(t)

	// Create Valid Alert
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Delete alert with Invalid filter
	w := lapi.RecordResponse("DELETE", "/v1/decisions?test=test", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	err_resp, _, err := readDecisionsErrorResp(w)
	assert.NoError(t, err)
	assert.Equal(t, err_resp["message"], "'test' doesn't exist: invalid filter")

	// Delete all alert
	w = lapi.RecordResponse("DELETE", "/v1/decisions", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _, err := readDecisionsDeleteResp(w)
	assert.NoError(t, err)
	assert.Equal(t, resp.NbDeleted, "3")
}

func TestStreamStartDecisionDedup(t *testing.T) {
	//Ensure that at stream startup we only get the longest decision
	lapi := SetupLAPITest(t)

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	lapi.InsertAlertFromFile("./tests/alert_sample.json")

	// Get Stream, we only get one decision (the longest one)
	w := lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err := readDecisionsStreamResp(w)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))
	assert.Equal(t, int64(3), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w = lapi.RecordResponse("DELETE", "/v1/decisions/3", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// Get Stream, we only get one decision (the longest one, id=2)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))
	assert.Equal(t, int64(2), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w = lapi.RecordResponse("DELETE", "/v1/decisions/2", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// And get the remaining decision (1)
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 0, len(decisions["deleted"]))
	assert.Equal(t, 1, len(decisions["new"]))
	assert.Equal(t, int64(1), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete the last decision, we receive the delete order
	w = lapi.RecordResponse("DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	//and now we only get a deleted decision
	w = lapi.RecordResponse("GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code, err = readDecisionsStreamResp(w)
	assert.Equal(t, nil, err)
	assert.Equal(t, 200, code)
	assert.Equal(t, 1, len(decisions["deleted"]))
	assert.Equal(t, int64(1), decisions["deleted"][0].ID)
	assert.Equal(t, "test", *decisions["deleted"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["deleted"][0].Value)
	assert.Equal(t, 0, len(decisions["new"]))
}

type DecisionCheck struct {
	ID       int64
	Origin   string
	Scenario string
	Value    string
	Duration string
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

func TestStreamDecisionStart(t *testing.T) {
	lapi := SetupLAPITest(t)

	/*
		Create multiple alerts:
		  - 3 alerts for 127.0.0.1 with ID 1/2/3   : Different duration / scenario / origin
		  - 3 alerts for 127.0.0.2 with ID 4/5/6/7 : Different duration / scenario / origin
	*/
	lapi.InsertAlertFromFile("./tests/alert_duplicate.json")

	tests := []DecisionTest{
		{
			TestName:      "test startup",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(3),
					Origin:   "test",
					Scenario: "crowdsecurity/longest",
					Value:    "127.0.0.1",
					Duration: "4h59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with scenarios containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_containing=ssh_bf",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(2),
					Origin:   "another_origin",
					Scenario: "crowdsecurity/ssh_bf",
					Value:    "127.0.0.1",
					Duration: "2h59",
				},
				{
					ID:       int64(5),
					Origin:   "test",
					Scenario: "crowdsecurity/ssh_bf",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with multiple scenarios containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_containing=ssh_bf,test",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{
				{
					ID:       int64(2),
					Origin:   "another_origin",
					Scenario: "crowdsecurity/ssh_bf",
					Value:    "127.0.0.1",
					Duration: "2h59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with unknown scenarios containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_containing=unknown",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        0,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{},
		},
		{
			TestName:      "test startup with scenarios containing and not containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_containing=test&scenarios_not_containing=ssh_bf",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(1),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.1",
					Duration: "59m",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with scenarios containing and not containing 2",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_containing=longest&scenarios_not_containing=ssh_bf,test",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        1,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(3),
					Origin:   "test",
					Scenario: "crowdsecurity/longest",
					Value:    "127.0.0.1",
					Duration: "4h59",
				},
			},
		},
		{
			TestName:      "test startup with scenarios not containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh_bf",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{
				{
					ID:       int64(3),
					Origin:   "test",
					Scenario: "crowdsecurity/longest",
					Value:    "127.0.0.1",
					Duration: "4h59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with multiple scenarios not containing",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&scenarios_not_containing=ssh_bf,test",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        1,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{
				{
					ID:       int64(3),
					Origin:   "test",
					Scenario: "crowdsecurity/longest",
					Value:    "127.0.0.1",
					Duration: "4h59",
				},
			},
		},
		{
			TestName:      "test startup with origins parameter",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&origins=another_origin",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{
				{
					ID:       int64(2),
					Origin:   "another_origin",
					Scenario: "crowdsecurity/ssh_bf",
					Value:    "127.0.0.1",
					Duration: "2h59",
				},
				{
					ID:       int64(7),
					Origin:   "another_origin",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "1h59",
				},
			},
		},
		{
			TestName:      "test startup with multiple origins parameter",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&origins=another_origin,test",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},

			NewChecks: []DecisionCheck{
				{
					ID:       int64(3),
					Origin:   "test",
					Scenario: "crowdsecurity/longest",
					Value:    "127.0.0.1",
					Duration: "4h59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "test startup with unknown origins",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true&origins=unknown",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        0,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks:     []DecisionCheck{},
		},
		{
			TestName:      "delete decisions 3 (127.0.0.1)",
			Method:        "DELETE",
			Route:         "/v1/decisions/3",
			CheckCodeOnly: true,
			Code:          200,
			LenNew:        0,
			LenDeleted:    0,
			AuthType:      PASSWORD,
			DelChecks:     []DecisionCheck{},
			NewChecks:     []DecisionCheck{},
		},
		{
			TestName:      "check that 127.0.0.1 is not in deleted IP",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(2),
					Origin:   "another_origin",
					Scenario: "crowdsecurity/ssh_bf",
					Value:    "127.0.0.1",
					Duration: "2h59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "delete decisions 2 (127.0.0.1)",
			Method:        "DELETE",
			Route:         "/v1/decisions/2",
			CheckCodeOnly: true,
			Code:          200,
			LenNew:        0,
			LenDeleted:    0,
			AuthType:      PASSWORD,
			DelChecks:     []DecisionCheck{},
			NewChecks:     []DecisionCheck{},
		},
		{
			TestName:      "check that 127.0.0.1 is not in deleted IP",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        2,
			LenDeleted:    0,
			AuthType:      APIKEY,
			DelChecks:     []DecisionCheck{},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(1),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.1",
					Duration: "59",
				},
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
		{
			TestName:      "delete decisions 1 (127.0.0.1)",
			Method:        "DELETE",
			Route:         "/v1/decisions/1",
			CheckCodeOnly: true,
			Code:          200,
			LenNew:        0,
			LenDeleted:    0,
			AuthType:      PASSWORD,
			DelChecks:     []DecisionCheck{},
			NewChecks:     []DecisionCheck{},
		},
		{
			TestName:      "127.0.0.1 should be in deleted now",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true",
			CheckCodeOnly: false,
			Code:          200,
			LenNew:        1,
			LenDeleted:    1,
			AuthType:      APIKEY,
			DelChecks: []DecisionCheck{
				{
					ID:       int64(1),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.1",
					Duration: "-", // we check that the time is negative
				},
			},
			NewChecks: []DecisionCheck{
				{
					ID:       int64(4),
					Origin:   "test",
					Scenario: "crowdsecurity/test",
					Value:    "127.0.0.2",
					Duration: "2h59",
				},
			},
		},
	}

	for _, test := range tests {
		runTest(lapi, test, t)
	}
}

func TestStreamDecision(t *testing.T) {

	/*
		Create multiple alerts:
		  - 3 alerts for 127.0.0.1 with ID 1/2/3   : Different duration / scenario / origin
		  - 3 alerts for 127.0.0.2 with ID 4/5/6/7 : Different duration / scenario / origin
	*/

	// this test just init the stream with startup=true
	preTests := []DecisionTest{
		{
			TestName:      "test startup",
			Method:        "GET",
			Route:         "/v1/decisions/stream?startup=true",
			CheckCodeOnly: false,
			Code:          200,
			AuthType:      APIKEY,
			LenNew:        0,
			LenDeleted:    0,
			DelChecks:     []DecisionCheck{},
			NewChecks:     []DecisionCheck{},
		},
	}

	tests := map[string][]DecisionTest{
		"Test without parameter": {
			{
				TestName:      "get stream",
				Method:        "GET",
				Route:         "/v1/decisions/stream",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        2,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks: []DecisionCheck{
					{
						ID:       int64(3),
						Origin:   "test",
						Scenario: "crowdsecurity/longest",
						Value:    "127.0.0.1",
						Duration: "4h59",
					},
					{
						ID:       int64(4),
						Origin:   "test",
						Scenario: "crowdsecurity/test",
						Value:    "127.0.0.2",
						Duration: "2h59",
					},
				},
			},
			{
				TestName:      "delete decisions 3 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/3",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not in deleted IP",
				Method:        "GET",
				Route:         "/v1/decisions/stream",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "delete decisions 2 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/2",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not in deleted IP",
				Method:        "GET",
				Route:         "/v1/decisions/stream",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			}, /*
				{
					TestName:      "delete decisions 1 (127.0.0.1)",
					Method:        "DELETE",
					Route:         "/v1/decisions/1",
					CheckCodeOnly: true,
					Code:          200,
					LenNew:        0,
					LenDeleted:    0,
					AuthType:      PASSWORD,
					DelChecks:     []DecisionCheck{},
					NewChecks:     []DecisionCheck{},
				},
				{
					TestName:      "127.0.0.1 should be in deleted now",
					Method:        "GET",
					Route:         "/v1/decisions/stream",
					CheckCodeOnly: false,
					Code:          200,
					LenNew:        0,
					LenDeleted:    1,
					AuthType:      APIKEY,
					DelChecks: []DecisionCheck{
						{
							ID:       int64(1),
							Origin:   "test",
							Scenario: "crowdsecurity/test",
							Value:    "127.0.0.1",
							Duration: "-",
						},
					},
					NewChecks: []DecisionCheck{},
				},*/
		},
		"test with scenarios containing": {
			{
				TestName:      "get stream",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        2,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks: []DecisionCheck{
					{
						ID:       int64(2),
						Origin:   "another_origin",
						Scenario: "crowdsecurity/ssh_bf",
						Value:    "127.0.0.1",
						Duration: "2h59",
					},
					{
						ID:       int64(5),
						Origin:   "test",
						Scenario: "crowdsecurity/ssh_bf",
						Value:    "127.0.0.2",
						Duration: "2h59",
					},
				},
			},
			{
				TestName:      "delete decisions 3 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/3",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not in deleted IP",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "delete decisions 2 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/2",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is deleted (decision for ssh_bf was with ID 2)",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    1,
				AuthType:      APIKEY,
				DelChecks: []DecisionCheck{
					{
						ID:       int64(2),
						Origin:   "another_origin",
						Scenario: "crowdsecurity/ssh_bf",
						Value:    "127.0.0.1",
						Duration: "-",
					},
				},
				NewChecks: []DecisionCheck{},
			},
		},
		"test with scenarios not containing": {
			{
				TestName:      "get stream",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_not_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        2,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks: []DecisionCheck{
					{
						ID:       int64(3),
						Origin:   "test",
						Scenario: "crowdsecurity/longest",
						Value:    "127.0.0.1",
						Duration: "4h59",
					},
					{
						ID:       int64(4),
						Origin:   "test",
						Scenario: "crowdsecurity/test",
						Value:    "127.0.0.2",
						Duration: "2h59",
					},
				},
			},
			{
				TestName:      "delete decisions 3 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/3",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not in deleted IP",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_not_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			/*{
				TestName:      "delete decisions 2 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/2",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not deleted",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_not_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "delete decisions 1 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/1",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is deleted",
				Method:        "GET",
				Route:         "/v1/decisions/stream?scenarios_not_containing=ssh_bf",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    1,
				AuthType:      APIKEY,
				DelChecks: []DecisionCheck{
					{
						ID:       int64(1),
						Origin:   "test",
						Scenario: "crowdsecurity/test",
						Value:    "127.0.0.1",
						Duration: "-",
					},
				},
				NewChecks: []DecisionCheck{},
			},*/
		},
		"test with origins": {
			{
				TestName:      "get stream",
				Method:        "GET",
				Route:         "/v1/decisions/stream?origins=another_origin",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        2,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks: []DecisionCheck{
					{
						ID:       int64(2),
						Origin:   "another_origin",
						Scenario: "crowdsecurity/ssh_bf",
						Value:    "127.0.0.1",
						Duration: "2h59",
					},
					{
						ID:       int64(7),
						Origin:   "another_origin",
						Scenario: "crowdsecurity/test",
						Value:    "127.0.0.2",
						Duration: "1h59",
					},
				},
			},
			{
				TestName:      "delete decisions 3 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/3",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is not in deleted IP",
				Method:        "GET",
				Route:         "/v1/decisions/stream?origins=another_origin",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      APIKEY,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "delete decisions 2 (127.0.0.1)",
				Method:        "DELETE",
				Route:         "/v1/decisions/2",
				CheckCodeOnly: true,
				Code:          200,
				LenNew:        0,
				LenDeleted:    0,
				AuthType:      PASSWORD,
				DelChecks:     []DecisionCheck{},
				NewChecks:     []DecisionCheck{},
			},
			{
				TestName:      "check that 127.0.0.1 is deleted",
				Method:        "GET",
				Route:         "/v1/decisions/stream?origins=another_origin",
				CheckCodeOnly: false,
				Code:          200,
				LenNew:        0,
				LenDeleted:    1,
				AuthType:      APIKEY,
				DelChecks: []DecisionCheck{
					{
						ID:       int64(2),
						Origin:   "another_origin",
						Scenario: "crowdsecurity/ssh_bf",
						Value:    "127.0.0.1",
						Duration: "-",
					},
				},
				NewChecks: []DecisionCheck{},
			},
		},
	}

	// run tests for the stream
	for testName, test := range tests {

		// init a new LAPI
		lapi := SetupLAPITest(t)

		// run pre-test, mostly to init the stream
		for _, test := range preTests {
			runTest(lapi, test, t)
		}
		// insert decisions now that the stream is initiated
		lapi.InsertAlertFromFile("./tests/alert_duplicate.json")

		for _, oneTest := range test {
			oneTest.TestName = fmt.Sprintf("%s (%s)", oneTest.TestName, testName)
			runTest(lapi, oneTest, t)
		}

		// clean the db after each test
		//os.Remove(lapi.DBConfig.DbPath)
	}
}

func runTest(lapi LAPI, test DecisionTest, t *testing.T) {
	w := lapi.RecordResponse(test.Method, test.Route, emptyBody, test.AuthType)
	assert.Equal(t, test.Code, w.Code)
	if test.CheckCodeOnly {
		return
	}
	decisions, _, err := readDecisionsStreamResp(w)
	assert.Equal(t, nil, err)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	assert.Equal(t, test.LenDeleted, len(decisions["deleted"]), fmt.Sprintf("'%s': len(deleted)", test.TestName))
	assert.Equal(t, test.LenNew, len(decisions["new"]), fmt.Sprintf("'%s': len(new)", test.TestName))

	for i, check := range test.NewChecks {
		assert.Equal(t, check.ID, decisions["new"][i].ID, fmt.Sprintf("'%s' (idx: %d): field: ID", test.TestName, i))
		assert.Equal(t, check.Origin, *decisions["new"][i].Origin, fmt.Sprintf("'%s' (idx: %d): field: Origin", test.TestName, i))
		assert.Equal(t, check.Scenario, *decisions["new"][i].Scenario, fmt.Sprintf("'%s' (idx: %d): field: Scenario", test.TestName, i))
		assert.Equal(t, check.Value, *decisions["new"][i].Value, fmt.Sprintf("'%s' (idx: %d): field: Value", test.TestName, i))
		assert.Contains(t, *decisions["new"][i].Duration, check.Duration, fmt.Sprintf("'%s' (idx: %d): field: Duration", test.TestName, i))
	}

	for i, check := range test.DelChecks {
		assert.Equal(t, check.ID, decisions["deleted"][i].ID, fmt.Sprintf("'%s' (idx: %d): field: ID", test.TestName, i))
		assert.Equal(t, check.Origin, *decisions["deleted"][i].Origin, fmt.Sprintf("'%s' (idx: %d): field: Origin", test.TestName, i))
		assert.Equal(t, check.Scenario, *decisions["deleted"][i].Scenario, fmt.Sprintf("'%s' (idx: %d): field: Scenario", test.TestName, i))
		assert.Equal(t, check.Value, *decisions["deleted"][i].Value, fmt.Sprintf("'%s' (idx: %d): field: Value", test.TestName, i))
		assert.Contains(t, *decisions["deleted"][i].Duration, check.Duration, fmt.Sprintf("'%s' (idx: %d): field: Duration", test.TestName, i))
	}
}
