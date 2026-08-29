package apiserver

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csnet"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

const (
	APIKEY   = "apikey"
	PASSWORD = "password"
)

func TestDeleteDecisionRange(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk.json")

	// delete by ip wrong
	w := lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?range=1.2.3.0/24", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by range

	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"2"}`, w.Body.String())

	// delete by range : ensure it was already deleted

	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?range=91.121.79.0/24", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"0"}`, w.Body.String())
}

func TestDeleteDecisionFilter(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk.json")

	// delete by ip wrong

	w := lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?ip=1.2.3.4", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by ip good

	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?ip=91.121.79.179", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"1"}`, w.Body.String())

	// delete by scope/value

	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?scopes=Ip&value=91.121.79.178", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"1"}`, w.Body.String())
}

func TestDeleteDecisionFilterByScenario(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk.json")

	// delete by wrong scenario

	w := lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?scenario=crowdsecurity/ssh-bff", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"0"}`, w.Body.String())

	// delete by scenario good

	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?scenario=crowdsecurity/ssh-bf", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"nbDeleted":"2"}`, w.Body.String())
}

func TestGetDecisionFilters(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk.json")

	// Get Decision

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code := readDecisionsGetResp(t, w)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 2)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[1].Scenario)
	assert.Equal(t, "91.121.79.178", *decisions[1].Value)
	assert.Equal(t, int64(2), decisions[1].ID)

	// Get Decision : type filter

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions?type=ban", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code = readDecisionsGetResp(t, w)
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

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions?scopes=Ip&value=91.121.79.179", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code = readDecisionsGetResp(t, w)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 1)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get Decision : ip filter

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions?ip=91.121.79.179", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code = readDecisionsGetResp(t, w)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 1)
	assert.Equal(t, "crowdsecurity/ssh-bf", *decisions[0].Scenario)
	assert.Equal(t, "91.121.79.179", *decisions[0].Value)
	assert.Equal(t, int64(1), decisions[0].ID)

	// assert.Contains(t, w.Body.String(), `"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.179"`)
	// assert.NotContains(t, w.Body.String(), `"id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"91.121.79.178"`)

	// Get decision : by range
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions?range=91.121.79.0/24&contains=false", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code = readDecisionsGetResp(t, w)
	assert.Equal(t, 200, code)
	assert.Len(t, decisions, 2)
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.179")
	assert.Contains(t, []string{*decisions[0].Value, *decisions[1].Value}, "91.121.79.178")
}

func TestGetDecision(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Get Decision
	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	decisions, code := readDecisionsGetResp(t, w)
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
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions?test=test", emptyBody, APIKEY)
	assert.Equal(t, 200, w.Code)
	assert.Len(t, decisions, 3)
}

func TestDeleteDecisionByID(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Have one alert
	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code := readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)

	// Delete alert with Invalid ID
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/test", emptyBody, PASSWORD)
	assert.Equal(t, 400, w.Code)
	errResp, _ := readDecisionsErrorResp(t, w)
	assert.Equal(t, "decision_id must be valid integer", errResp["message"])

	// Delete alert with ID that not exist
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/100", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	errResp, _ = readDecisionsErrorResp(t, w)
	assert.Equal(t, "decision with id '100' doesn't exist: unable to delete", errResp["message"])

	// Have one alert
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)

	// Delete alert with valid ID
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _ := readDecisionsDeleteResp(t, w)
	assert.Equal(t, "1", resp.NbDeleted)

	// Have one alert (because we delete an alert that has dup targets)
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
}

func TestDeleteDecision(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Delete alert with Invalid filter
	w := lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions?test=test", emptyBody, PASSWORD)
	assert.Equal(t, 500, w.Code)
	errResp, _ := readDecisionsErrorResp(t, w)
	assert.Equal(t, "'test' doesn't exist: invalid filter", errResp["message"])

	// Delete all alert
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)
	resp, _ := readDecisionsDeleteResp(t, w)
	assert.Equal(t, "3", resp.NbDeleted)
}

func TestStreamStartDecisionDedup(t *testing.T) {
	ctx := t.Context()

	// Ensure that at stream startup we only get the longest decision
	lapi := SetupLAPITest(t, ctx)

	// Create Valid Alert : 3 decisions for 127.0.0.1, longest has id=3
	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	// Get Stream, we only get one decision (the longest one)
	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code := readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(3), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// id=3 decision is deleted, this won't affect `deleted`, because there are decisions on the same ip
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/3", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// Get Stream, we only get one decision (the longest one, id=2)
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(2), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete another decision, yet don't receive it in stream, since there's another decision on same IP
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/2", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// And get the remaining decision (1)
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	assert.Equal(t, 200, code)
	assert.Empty(t, decisions["deleted"])
	assert.Len(t, decisions["new"], 1)
	assert.Equal(t, int64(1), decisions["new"][0].ID)
	assert.Equal(t, "test", *decisions["new"][0].Origin)
	assert.Equal(t, "127.0.0.1", *decisions["new"][0].Value)

	// We delete the last decision, we receive the delete order
	w = lapi.RecordResponse(t, ctx, "DELETE", "/v1/decisions/1", emptyBody, PASSWORD)
	assert.Equal(t, 200, w.Code)

	// and now we only get a deleted decision
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
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

// Regression for cs-firewall-bouncer#508.
//
// A blocklist import stamps created_at inside its transaction, so a decision can commit after a
// pull that could not see it, carrying a created_at older than that pull. Keyed on a timestamp
// such a decision is skipped by every later delta and only comes back on a full resync; keyed on
// the id cursor it is delivered on the next pull.
func TestStreamDecisionLateCommit(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	// A first pull establishes the bouncer position.
	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	_, code := readDecisionsStreamResp(t, w)
	require.Equal(t, 200, code)

	// A decision whose transaction started before that pull and committed after it.
	_, err := lapi.DBClient.Ent.Decision.Create().
		SetCreatedAt(time.Now().UTC().Add(-time.Hour)).
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario("test/late-commit").
		SetType("ban").
		SetScope("Ip").
		SetValue("11.22.33.44").
		SetOrigin("lists").
		Save(ctx)
	require.NoError(t, err)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream", emptyBody, APIKEY)
	decisions, code := readDecisionsStreamResp(t, w)
	require.Equal(t, 200, code)
	require.Len(t, decisions["new"], 1)
	require.Equal(t, "11.22.33.44", *decisions["new"][0].Value)

	// And it is not resent once the cursor has moved past it.
	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	require.Equal(t, 200, code)
	require.Empty(t, decisions["new"])
}

// A cursor past the end of the decisions table (partial restore, or MySQL < 8.0 recomputing
// AUTO_INCREMENT) must fall back to a full resync rather than silently starving the bouncer.
func TestStreamDecisionCursorAheadOfTable(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	lapi.InsertAlertFromFile(t, ctx, "./tests/alert_sample.json")

	w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
	decisions, code := readDecisionsStreamResp(t, w)
	require.Equal(t, 200, code)
	require.Len(t, decisions["new"], 1)

	_, err := lapi.DBClient.Ent.Bouncer.Update().SetStreamCursor(999999).Save(ctx)
	require.NoError(t, err)

	w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream", emptyBody, APIKEY)
	decisions, code = readDecisionsStreamResp(t, w)
	require.Equal(t, 200, code)
	require.Len(t, decisions["new"], 1)
}

// The delta is now driven by the id cursor rather than a timestamp, so every filter has to keep
// working on top of it, and the cursor has to advance even when a filter matches nothing.
func TestStreamDecisionDeltaFilters(t *testing.T) {
	seed := func(t *testing.T, ctx context.Context, lapi LAPI) {
		t.Helper()

		seedOne(t, ctx, lapi, "1.0.0.1", "lists", "crowdsecurity/ssh_bf", types.Ip, "ban")
		seedOne(t, ctx, lapi, "1.0.0.2", "crowdsec", "crowdsecurity/http_probing", types.Ip, "ban")
		seedOne(t, ctx, lapi, "1.0.0.3", "CAPI", "crowdsecurity/ssh_bf", types.Ip, "captcha")
		seedOne(t, ctx, lapi, "someuser", "crowdsec", "crowdsecurity/test", "user", "ban")
	}

	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{"no filter", "", []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"}},
		{"origins", "&origins=lists", []string{"1.0.0.1"}},
		{"multiple origins", "&origins=lists,CAPI", []string{"1.0.0.1", "1.0.0.3"}},
		{"unknown origin", "&origins=nope", nil},
		{"scenarios_containing", "&scenarios_containing=ssh_bf", []string{"1.0.0.1", "1.0.0.3"}},
		{"scenarios_not_containing", "&scenarios_not_containing=ssh_bf", []string{"1.0.0.2"}},
		{"multiple scenarios_containing", "&scenarios_containing=ssh_bf,http_probing", []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"}},
		{"unknown scenarios_containing", "&scenarios_containing=nope", nil},
		{"scopes", "&scopes=user", []string{"someuser"}},
		{"scopes ip+user", "&scopes=ip,user", []string{"1.0.0.1", "1.0.0.2", "1.0.0.3", "someuser"}},
		{"value", "&value=1.0.0.2", []string{"1.0.0.2"}},
		{"type", "&type=captcha", []string{"1.0.0.3"}},
		{"ip", "&ip=1.0.0.1", []string{"1.0.0.1"}},
		{"range", "&range=1.0.0.0/30&contains=false", []string{"1.0.0.1", "1.0.0.2", "1.0.0.3"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			lapi := SetupLAPITest(t, ctx)

			// decisions already delivered before the cursor was parked: they match several of
			// the filters below, so they resurface if the cursor is ignored
			lapi.InsertAlertFromFile(t, ctx, "./tests/alert_minibulk.json")
			seedOne(t, ctx, lapi, "9.9.9.9", "lists", "crowdsecurity/ssh_bf", types.Ip, "ban")

			w := lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
			_, code := readDecisionsStreamResp(t, w)
			require.Equal(t, 200, code)

			before, err := lapi.DBClient.LatestDecisionID(ctx)
			require.NoError(t, err)
			require.NotZero(t, before, "cursor must be non-zero so the delta really is id > cursor")

			seed(t, ctx, lapi)

			w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?"+tc.query, emptyBody, APIKEY)
			decisions, code := readDecisionsStreamResp(t, w)
			require.Equal(t, 200, code)

			got := make([]string, 0, len(decisions["new"]))
			for _, d := range decisions["new"] {
				got = append(got, *d.Value)
			}

			sort.Strings(got)
			require.Equal(t, tc.want, nilIfEmpty(got))

			// the cursor advances to the end of the table whatever the filter matched,
			// otherwise a filtered bouncer would rescan a widening range forever
			latest, err := lapi.DBClient.LatestDecisionID(ctx)
			require.NoError(t, err)

			b, err := lapi.DBClient.Ent.Bouncer.Get(ctx, 1)
			require.NoError(t, err)
			require.Equal(t, latest, b.StreamCursor)

			// and nothing is resent
			w = lapi.RecordResponse(t, ctx, "GET", "/v1/decisions/stream?"+tc.query, emptyBody, APIKEY)
			decisions, code = readDecisionsStreamResp(t, w)
			require.Equal(t, 200, code)
			require.Empty(t, decisions["new"])
		})
	}
}

func seedOne(t *testing.T, ctx context.Context, lapi LAPI, value, origin, scenario, scope, dtype string) {
	t.Helper()

	rng, err := csnet.NewRange(value)
	if scope == types.Ip {
		require.NoError(t, err)
	}

	_, err = lapi.DBClient.Ent.Decision.Create().
		SetUntil(time.Now().UTC().Add(time.Hour)).
		SetScenario(scenario).
		SetType(dtype).
		SetScope(scope).
		SetValue(value).
		SetOrigin(origin).
		SetStartIP(rng.Start.Addr).
		SetEndIP(rng.End.Addr).
		SetIPSize(int64(rng.Size())).
		Save(ctx)
	require.NoError(t, err)
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}

	return s
}
