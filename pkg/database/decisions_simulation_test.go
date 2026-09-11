package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func TestDecisionSimulationOverlap(t *testing.T) {
	for _, scope := range []string{"Ip", "Range"} {
		t.Run(scope, func(t *testing.T) {
			ctx := t.Context()
			c := getDBClient(t, ctx)
			t.Cleanup(func() { require.NoError(t, c.Close()) })
			now := time.Now().UTC()
			value := "192.0.2.213"
			if scope == "Range" {
				value = "192.0.2.0/24"
			}
			seed := func(simulated bool, duration time.Duration) *ent.Decision {
				d, err := c.Ent.Decision.Create().
					SetUntil(now.Add(duration)).
					SetScenario("test/simulation-overlap").
					SetType("ban").SetScope(scope).SetValue(value).
					SetOrigin("crowdsec").SetSimulated(simulated).Save(ctx)
				require.NoError(t, err)
				return d
			}
			first := seed(false, time.Hour)
			last := seed(false, 2*time.Hour)
			shortSimulation := seed(true, 3*time.Hour)
			longSimulation := seed(true, 4*time.Hour)
			since := now.Add(-time.Minute)

			// Advance the query time to exercise expiry without changing rows or sleeping.
			for _, tc := range []struct {
				name    string
				query   string
				after   time.Duration
				filters map[string][]string
				wantIDs []int
			}{
				{name: "active", query: "active", wantIDs: []int{last.ID}},
				{name: "active_after_first_expiry", query: "active", after: 90 * time.Minute, wantIDs: []int{last.ID}},
				{name: "startup_before_last_expiry", query: "expired", after: 90 * time.Minute},
				{name: "delta_before_last_expiry", query: "expired_since", after: 90 * time.Minute},
				{name: "active_after_last_expiry", query: "active", after: 150 * time.Minute},
				{name: "startup_after_last_expiry", query: "expired", after: 150 * time.Minute, wantIDs: []int{last.ID}},
				{name: "delta_after_last_expiry", query: "expired_since", after: 150 * time.Minute, wantIDs: []int{last.ID}},
				{
					name: "include_simulated_active", query: "active",
					filters: map[string][]string{"simulated": {"true"}},
					wantIDs: []int{last.ID, longSimulation.ID},
				},
				{
					name: "include_simulated_expired", query: "expired", after: 5 * time.Hour,
					filters: map[string][]string{"simulated": {"true"}},
					wantIDs: []int{last.ID, longSimulation.ID},
				},
				{
					name: "without_dedup", query: "active",
					filters: map[string][]string{"dedup": {"false"}},
					wantIDs: []int{first.ID, last.ID},
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var (
						got []*ent.Decision
						err error
					)
					queryTime := now.Add(tc.after)
					switch tc.query {
					case "active":
						got, err = c.QueryAllDecisionsWithFilters(ctx, queryTime, tc.filters)
					case "expired":
						got, err = c.QueryExpiredDecisionsWithFilters(ctx, queryTime, tc.filters)
					case "expired_since":
						got, err = c.QueryExpiredDecisionsSinceWithFilters(ctx, queryTime, &since, tc.filters)
					default:
						t.Fatalf("unknown query %q", tc.query)
					}
					require.NoError(t, err)
					var gotIDs []int
					for _, d := range got {
						gotIDs = append(gotIDs, d.ID)
					}
					require.Equal(t, tc.wantIDs, gotIDs)
				})
			}

			for _, original := range []*ent.Decision{first, last, shortSimulation, longSimulation} {
				preserved, err := c.Ent.Decision.Get(ctx, original.ID)
				require.NoError(t, err)
				require.Equal(t, original.Simulated, preserved.Simulated)
				require.Equal(t, original.Until, preserved.Until)
			}
		})
	}
}
