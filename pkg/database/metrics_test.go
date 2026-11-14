package database

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
)

func TestGetUnsentMetrics(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)

	now := time.Now().UTC()

	// 3 unsent LP rows, 2 unsent RC rows, and one that was already pushed
	ids := make([]int, 0, 6)

	for i := range 3 {
		m, err := dbClient.CreateMetric(ctx, metric.GeneratedTypeLP, "lp1", now.Add(time.Duration(i)*time.Minute), `{"metrics":[]}`)
		require.NoError(t, err)
		ids = append(ids, m.ID)
	}

	for range 2 {
		m, err := dbClient.CreateMetric(ctx, metric.GeneratedTypeRC, "rc1", now, `{"metrics":[]}`)
		require.NoError(t, err)
		ids = append(ids, m.ID)
	}

	pushed, err := dbClient.CreateMetric(ctx, metric.GeneratedTypeLP, "lp1", now, `{"metrics":[]}`)
	require.NoError(t, err)
	require.NoError(t, dbClient.MarkUsageMetricsAsSent(ctx, []int{pushed.ID}))

	tests := []struct {
		name     string
		afterID  int
		limit    int
		expected []int
	}{
		{
			name:     "everything pending, both types, already pushed rows excluded",
			afterID:  0,
			limit:    10,
			expected: ids,
		},
		{
			name:     "limit is honored, rows come back in id order",
			afterID:  0,
			limit:    2,
			expected: ids[:2],
		},
		{
			name:     "afterID skips the rows already consumed",
			afterID:  ids[2],
			limit:    10,
			expected: ids[3:],
		},
		{
			name:     "nothing left after the last row",
			afterID:  ids[len(ids)-1],
			limit:    10,
			expected: []int{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			metrics, err := dbClient.GetUnsentMetrics(ctx, tc.afterID, tc.limit)
			require.NoError(t, err)

			got := make([]int, 0, len(metrics))
			for _, m := range metrics {
				got = append(got, m.ID)
			}

			require.Equal(t, tc.expected, got)
		})
	}
}

func TestMarkStaleUsageMetricsAsSent(t *testing.T) {
	ctx := t.Context()
	dbClient := getDBClient(t, ctx)

	now := time.Now().UTC()

	stale, err := dbClient.CreateMetric(ctx, metric.GeneratedTypeLP, "lp1", now.Add(-48*time.Hour), `{"metrics":[]}`)
	require.NoError(t, err)

	fresh, err := dbClient.CreateMetric(ctx, metric.GeneratedTypeLP, "lp1", now, `{"metrics":[]}`)
	require.NoError(t, err)

	dropped, err := dbClient.MarkStaleUsageMetricsAsSent(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, dropped)

	pending, err := dbClient.GetUnsentMetrics(ctx, 0, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, fresh.ID, pending[0].ID)

	// running it again is a no-op: the stale row is no longer pending
	dropped, err = dbClient.MarkStaleUsageMetricsAsSent(ctx, now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Zero(t, dropped)

	staleRow := dbClient.Ent.Metric.GetX(ctx, stale.ID)
	require.NotNil(t, staleRow.PushedAt)
}
