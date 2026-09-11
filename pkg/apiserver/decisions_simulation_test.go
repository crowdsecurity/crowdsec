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
	for _, mode := range []string{"startup", "delta_delete", "delta_new"} {
		for _, scope := range []string{"Ip", "Range"} {
			for _, secondReal := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/two_real_%t", mode, scope, secondReal), func(t *testing.T) {
					ctx := t.Context()
					lapi := SetupLAPITest(t, ctx)
					stream := "/v1/decisions/stream"
					if mode == "startup" {
						stream += "?startup=true"
					}
					if mode == "delta_new" {
						response := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/decisions/stream?startup=true", emptyBody, APIKEY)
						decisions, code := readDecisionsStreamResp(t, response)
						require.Equal(t, http.StatusOK, code)
						require.Empty(t, decisions["new"])
						require.Empty(t, decisions["deleted"])
					}
					value := "192.0.2.213"
					if scope == "Range" {
						value = "192.0.2.0/24"
					}
					seed := func(simulated bool, duration time.Duration) *ent.Decision {
						d, err := lapi.DBClient.Ent.Decision.Create().
							SetUntil(time.Now().UTC().Add(duration)).
							SetScenario("test/simulation-overlap").
							SetType("ban").SetScope(scope).SetValue(value).
							SetOrigin("crowdsec").SetSimulated(simulated).Save(ctx)
						require.NoError(t, err)
						return d
					}
					realDecision := seed(false, time.Hour)
					var simulated *ent.Decision
					if mode != "delta_delete" {
						simulated = seed(true, 4*time.Hour)
					}
					var other *ent.Decision
					if secondReal {
						other = seed(false, 2*time.Hour)
					}

					initialStream := "/v1/decisions/stream?startup=true"
					if mode == "delta_new" {
						initialStream = stream
					}
					response := lapi.RecordResponse(t, ctx, http.MethodGet, initialStream, emptyBody, APIKEY)
					decisions, code := readDecisionsStreamResp(t, response)
					require.Equal(t, http.StatusOK, code)
					require.Empty(t, decisions["deleted"])
					require.Len(t, decisions["new"], 1)
					wanted := realDecision.ID
					if secondReal {
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
					if secondReal {
						require.Empty(t, decisions["deleted"], "a live real decision still covers the value")
						if mode == "startup" {
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
	}
}
