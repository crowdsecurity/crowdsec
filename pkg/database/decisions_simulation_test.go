package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func TestDecisionSimulationOverlap(t *testing.T) {
	tests := []struct {
		name    string
		scope   string
		value   string
		query   string
		after   time.Duration
		filters map[string][]string
		want    []int
	}{
		{"Ip/active", "Ip", "192.0.2.213", "active", 0, nil, []int{1}},
		{"Ip/active after first expiry", "Ip", "192.0.2.213", "active", 90 * time.Minute, nil, []int{1}},
		{"Ip/startup before last expiry", "Ip", "192.0.2.213", "expired", 90 * time.Minute, nil, nil},
		{"Ip/delta before last expiry", "Ip", "192.0.2.213", "expired_since", 90 * time.Minute, nil, nil},
		{"Ip/active after last expiry", "Ip", "192.0.2.213", "active", 150 * time.Minute, nil, nil},
		{"Ip/startup after last expiry", "Ip", "192.0.2.213", "expired", 150 * time.Minute, nil, []int{1}},
		{"Ip/delta after last expiry", "Ip", "192.0.2.213", "expired_since", 150 * time.Minute, nil, []int{1}},
		{"Ip/explicit simulated false", "Ip", "192.0.2.213", "active", 0, map[string][]string{"simulated": {"false"}}, []int{1}},
		{"Ip/include simulated active", "Ip", "192.0.2.213", "active", 0, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Ip/include simulated before last expiry", "Ip", "192.0.2.213", "expired", 150 * time.Minute, map[string][]string{"simulated": {"true"}}, nil},
		{"Ip/include simulated delta before last expiry", "Ip", "192.0.2.213", "expired_since", 150 * time.Minute, map[string][]string{"simulated": {"true"}}, nil},
		{"Ip/include simulated expired", "Ip", "192.0.2.213", "expired", 5 * time.Hour, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Ip/include simulated expired delta", "Ip", "192.0.2.213", "expired_since", 5 * time.Hour, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Ip/without dedup", "Ip", "192.0.2.213", "active", 0, map[string][]string{"dedup": {"false"}}, []int{0, 1}},
		{"Ip/include simulated without dedup", "Ip", "192.0.2.213", "active", 0, map[string][]string{"simulated": {"true"}, "dedup": {"false"}}, []int{0, 1, 2, 3}},
		{"Range/active", "Range", "192.0.2.0/24", "active", 0, nil, []int{1}},
		{"Range/active after first expiry", "Range", "192.0.2.0/24", "active", 90 * time.Minute, nil, []int{1}},
		{"Range/startup before last expiry", "Range", "192.0.2.0/24", "expired", 90 * time.Minute, nil, nil},
		{"Range/delta before last expiry", "Range", "192.0.2.0/24", "expired_since", 90 * time.Minute, nil, nil},
		{"Range/active after last expiry", "Range", "192.0.2.0/24", "active", 150 * time.Minute, nil, nil},
		{"Range/startup after last expiry", "Range", "192.0.2.0/24", "expired", 150 * time.Minute, nil, []int{1}},
		{"Range/delta after last expiry", "Range", "192.0.2.0/24", "expired_since", 150 * time.Minute, nil, []int{1}},
		{"Range/explicit simulated false", "Range", "192.0.2.0/24", "active", 0, map[string][]string{"simulated": {"false"}}, []int{1}},
		{"Range/include simulated active", "Range", "192.0.2.0/24", "active", 0, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Range/include simulated before last expiry", "Range", "192.0.2.0/24", "expired", 150 * time.Minute, map[string][]string{"simulated": {"true"}}, nil},
		{"Range/include simulated delta before last expiry", "Range", "192.0.2.0/24", "expired_since", 150 * time.Minute, map[string][]string{"simulated": {"true"}}, nil},
		{"Range/include simulated expired", "Range", "192.0.2.0/24", "expired", 5 * time.Hour, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Range/include simulated expired delta", "Range", "192.0.2.0/24", "expired_since", 5 * time.Hour, map[string][]string{"simulated": {"true"}}, []int{3}},
		{"Range/without dedup", "Range", "192.0.2.0/24", "active", 0, map[string][]string{"dedup": {"false"}}, []int{0, 1}},
		{"Range/include simulated without dedup", "Range", "192.0.2.0/24", "active", 0, map[string][]string{"simulated": {"true"}, "dedup": {"false"}}, []int{0, 1, 2, 3}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			c := getDBClient(t, ctx)
			t.Cleanup(func() { require.NoError(t, c.Close()) })
			now := time.Now().UTC().Truncate(time.Second)
			seed := func(simulated bool, duration time.Duration) *ent.Decision {
				d, err := c.Ent.Decision.Create().
					SetUntil(now.Add(duration)).
					SetScenario("test/simulation-overlap").
					SetType("ban").
					SetScope(tc.scope).
					SetValue(tc.value).
					SetOrigin("crowdsec").
					SetSimulated(simulated).
					Save(ctx)
				require.NoError(t, err)

				return d
			}
			decisions := []*ent.Decision{
				seed(false, time.Hour),
				seed(false, 2*time.Hour),
				seed(true, 3*time.Hour),
				seed(true, 4*time.Hour),
			}

			// Advance the query time to exercise expiry without changing rows or sleeping.
			queryTime := now.Add(tc.after)
			since := now.Add(-time.Minute)
			var (
				got []*ent.Decision
				err error
			)
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

			var gotIDs, wantIDs []int
			for _, d := range got {
				gotIDs = append(gotIDs, d.ID)
			}
			for _, index := range tc.want {
				wantIDs = append(wantIDs, decisions[index].ID)
			}
			require.Equal(t, wantIDs, gotIDs)

			for _, original := range decisions {
				preserved, err := c.Ent.Decision.Get(ctx, original.ID)
				require.NoError(t, err)
				require.Equal(t, original.Simulated, preserved.Simulated)
				require.NotNil(t, preserved.Until)
				require.True(t, original.Until.Equal(*preserved.Until), "decision expiry should not change")
			}
		})
	}
}
