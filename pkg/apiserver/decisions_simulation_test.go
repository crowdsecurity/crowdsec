package apiserver

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func TestStreamDecisionSimulationOverlap(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		scope      string
		value      string
		secondReal bool
	}{
		{"startup/Ip/one real decision", "startup", "Ip", "192.0.2.213", false},
		{"startup/Ip/two real decisions", "startup", "Ip", "192.0.2.213", true},
		{"startup/Range/one real decision", "startup", "Range", "192.0.2.0/24", false},
		{"startup/Range/two real decisions", "startup", "Range", "192.0.2.0/24", true},
		{"delta_delete/Ip/one real decision", "delta_delete", "Ip", "192.0.2.213", false},
		{"delta_delete/Ip/two real decisions", "delta_delete", "Ip", "192.0.2.213", true},
		{"delta_delete/Range/one real decision", "delta_delete", "Range", "192.0.2.0/24", false},
		{"delta_delete/Range/two real decisions", "delta_delete", "Range", "192.0.2.0/24", true},
		{"delta_new/Ip/one real decision", "delta_new", "Ip", "192.0.2.213", false},
		{"delta_new/Ip/two real decisions", "delta_new", "Ip", "192.0.2.213", true},
		{"delta_new/Range/one real decision", "delta_new", "Range", "192.0.2.0/24", false},
		{"delta_new/Range/two real decisions", "delta_new", "Range", "192.0.2.0/24", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			lapi := SetupLAPITest(t, ctx)
			stream := "/v1/decisions/stream"
			if tc.mode == "startup" {
				stream += "?startup=true"
			}
			if tc.mode == "delta_new" {
				response := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
				decisions, code := readDecisionsStreamResp(t, response)
				require.Equal(t, http.StatusOK, code)
				require.Empty(t, decisions["new"])
				require.Empty(t, decisions["deleted"])
			}
			value := tc.value
			seed := func(simulated bool, duration time.Duration) *ent.Decision {
				d, err := lapi.DBClient.Ent.Decision.Create().
					SetUntil(time.Now().UTC().Add(duration)).
					SetScenario("test/simulation-overlap").
					SetType("ban").
					SetScope(tc.scope).
					SetValue(value).
					SetOrigin("crowdsec").
					SetSimulated(simulated).
					Save(ctx)
				require.NoError(t, err)
				return d
			}
			realDecision := seed(false, time.Hour)
			var simulated *ent.Decision
			if tc.mode != "delta_delete" {
				simulated = seed(true, 4*time.Hour)
			}
			var other *ent.Decision
			if tc.secondReal {
				other = seed(false, 2*time.Hour)
			}

			initialStream := "/v1/decisions/stream?startup=true"
			if tc.mode == "delta_new" {
				initialStream = stream
			}
			response := lapi.RecordResponse(t, ctx, http.MethodGet, initialStream, emptyBody, APIKEY)
			decisions, code := readDecisionsStreamResp(t, response)
			require.Equal(t, http.StatusOK, code)
			require.Empty(t, decisions["deleted"])
			require.Len(t, decisions["new"], 1)
			wanted := realDecision.ID
			if tc.secondReal {
				wanted = other.ID
			}
			require.Equal(t, int64(wanted), decisions["new"][0].ID)
			if simulated == nil {
				simulated = seed(true, 4*time.Hour)
			}

			response = lapi.RecordResponse(t, ctx, http.MethodDelete, fmt.Sprintf("/v1/decisions/%d", realDecision.ID), emptyBody, PASSWORD)
			require.Equal(t, http.StatusOK, response.Code)
			response = lapi.RecordResponse(t, ctx, http.MethodGet, stream, emptyBody, APIKEY)
			decisions, code = readDecisionsStreamResp(t, response)
			require.Equal(t, http.StatusOK, code)
			if tc.secondReal {
				require.Empty(t, decisions["deleted"], "a live real decision still covers the value")
				if tc.mode == "startup" {
					require.Len(t, decisions["new"], 1)
					require.Equal(t, int64(other.ID), decisions["new"][0].ID)
				}
				response = lapi.RecordResponse(t, ctx, http.MethodDelete, fmt.Sprintf("/v1/decisions/%d", other.ID), emptyBody, PASSWORD)
				require.Equal(t, http.StatusOK, response.Code)
				response = lapi.RecordResponse(t, ctx, http.MethodGet, stream, emptyBody, APIKEY)
				decisions, code = readDecisionsStreamResp(t, response)
				require.Equal(t, http.StatusOK, code)
				wanted = other.ID
			}
			require.Empty(t, decisions["new"])
			require.Len(t, decisions["deleted"], 1)
			require.Equal(t, int64(wanted), decisions["deleted"][0].ID)

			preserved, err := lapi.DBClient.Ent.Decision.Get(ctx, simulated.ID)
			require.NoError(t, err)
			require.True(t, preserved.Simulated)
			require.Equal(t, simulated.Until, preserved.Until)
		})
	}
}

func TestStreamDecisionIncludeSimulated(t *testing.T) {
	tests := []struct {
		name          string
		scope         string
		value         string
		startup       bool
		simulatedLast bool
	}{
		{"startup/Ip/simulated longest", "Ip", "192.0.2.213", true, true},
		{"startup/Ip/real longest", "Ip", "192.0.2.213", true, false},
		{"startup/Range/simulated longest", "Range", "192.0.2.0/24", true, true},
		{"startup/Range/real longest", "Range", "192.0.2.0/24", true, false},
		{"delta/Ip/simulated longest", "Ip", "192.0.2.213", false, true},
		{"delta/Ip/real longest", "Ip", "192.0.2.213", false, false},
		{"delta/Range/simulated longest", "Range", "192.0.2.0/24", false, true},
		{"delta/Range/real longest", "Range", "192.0.2.0/24", false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			lapi := SetupLAPITest(t, ctx)
			stream := "/v1/decisions/stream?simulated=true"
			if tc.startup {
				stream += "&startup=true"
			} else {
				response := lapi.RecordResponse(t, ctx, http.MethodGet, stream+"&startup=true", emptyBody, APIKEY)
				decisions, code := readDecisionsStreamResp(t, response)
				require.Equal(t, http.StatusOK, code)
				require.Empty(t, decisions["new"])
				require.Empty(t, decisions["deleted"])
			}

			var ids []int
			for i, simulated := range []bool{!tc.simulatedLast, tc.simulatedLast} {
				d, err := lapi.DBClient.Ent.Decision.Create().
					SetUntil(time.Now().UTC().Add(time.Duration(i+1) * time.Hour)).
					SetScenario("test/simulation-overlap").
					SetType("ban").
					SetScope(tc.scope).
					SetValue(tc.value).
					SetOrigin("crowdsec").
					SetSimulated(simulated).
					Save(ctx)
				require.NoError(t, err)
				ids = append(ids, d.ID)
			}

			response := lapi.RecordResponse(t, ctx, http.MethodGet, stream, emptyBody, APIKEY)
			decisions, code := readDecisionsStreamResp(t, response)
			require.Equal(t, http.StatusOK, code)
			require.Empty(t, decisions["deleted"])
			require.Len(t, decisions["new"], 1)
			require.Equal(t, int64(ids[1]), decisions["new"][0].ID)

			response = lapi.RecordResponse(t, ctx, http.MethodDelete, fmt.Sprintf("/v1/decisions/%d", ids[0]), emptyBody, PASSWORD)
			require.Equal(t, http.StatusOK, response.Code)
			response = lapi.RecordResponse(t, ctx, http.MethodGet, stream, emptyBody, APIKEY)
			decisions, code = readDecisionsStreamResp(t, response)
			require.Equal(t, http.StatusOK, code)
			require.Empty(t, decisions["deleted"], "the longest decision still covers the value")
			if tc.startup {
				require.Len(t, decisions["new"], 1)
				require.Equal(t, int64(ids[1]), decisions["new"][0].ID)
			} else {
				require.Empty(t, decisions["new"])
			}
		})
	}
}
