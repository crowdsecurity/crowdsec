package apiserver

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/metric"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

const usageMetricsURL = "http://api.crowdsec.net/api/usage-metrics"

// usageMetricsPayload is a stored metrics row: one window, padded to roughly size bytes so a test
// can decide how many of them fit in a batch.
func usageMetricsPayload(name string, size int) string {
	build := func(source string) string {
		return fmt.Sprintf(
			`{"metrics":[{"meta":{"utc_now_timestamp":42,"window_size_seconds":42},"items":[{"name":"read","unit":"line","value":42,"labels":{"source":%q}}]}]}`,
			source)
	}

	if padding := size - len(build(name)); padding > 0 {
		name += strings.Repeat("a", padding)
	}

	return build(name)
}

func addMachine(t *testing.T, ctx context.Context, api *apic, machineID string) {
	t.Helper()

	api.dbClient.Ent.Machine.Create().
		SetMachineId(machineID).
		SetPassword(testPassword.String()).
		SetIpAddress("1.2.3.4").
		SetScenarios("crowdsecurity/test").
		SetLastPush(time.Time{}).
		SetUpdatedAt(time.Time{}).
		ExecX(ctx)
}

func addBouncer(t *testing.T, ctx context.Context, api *apic, name string) {
	t.Helper()

	api.dbClient.Ent.Bouncer.Create().
		SetIPAddress("1.2.3.6").
		SetName(name).
		SetAPIKey("foobar").
		SetRevoked(false).
		SetLastPull(time.Time{}).
		ExecX(ctx)
}

func addMetrics(t *testing.T, ctx context.Context, api *apic, generatedType metric.GeneratedType, generatedBy string, receivedAt time.Time, payloads ...string) []int {
	t.Helper()

	ids := make([]int, 0, len(payloads))

	for _, payload := range payloads {
		row := api.dbClient.Ent.Metric.Create().
			SetGeneratedType(generatedType).
			SetGeneratedBy(generatedBy).
			SetReceivedAt(receivedAt).
			SetPayload(payload).
			SaveX(ctx)
		ids = append(ids, row.ID)
	}

	return ids
}

func pendingMetrics(t *testing.T, ctx context.Context, api *apic) []*ent.Metric {
	t.Helper()

	pending, err := api.dbClient.GetUnsentMetrics(ctx, 0, 1000)
	require.NoError(t, err)

	return pending
}

// mockCAPI answers every usage-metrics push with status, and records what was sent.
func mockCAPI(t *testing.T, api *apic, status int) *[]*models.AllMetrics {
	t.Helper()

	sent := &[]*models.AllMetrics{}

	httpmock.RegisterResponder("POST", usageMetricsURL, func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)

		if req.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(bytes.NewReader(body))
			require.NoError(t, err)

			body, err = io.ReadAll(reader)
			require.NoError(t, err)
		}

		require.Less(t, len(body), capiBodyLimit)

		received := &models.AllMetrics{}
		require.NoError(t, json.Unmarshal(body, received))

		*sent = append(*sent, received)

		return httpmock.NewBytesResponse(status, []byte("{}")), nil
	})

	apiURL, err := url.ParseRequestURI("http://api.crowdsec.net/")
	require.NoError(t, err)

	apiClient, err := apiclient.NewDefaultClient(apiURL, "/api", "", nil)
	require.NoError(t, err)

	api.apiClient = apiClient

	return sent
}

func windowCount(sent []*models.AllMetrics) int {
	count := 0

	for _, met := range sent {
		for _, lp := range met.LogProcessors {
			count += len(lp.Metrics)
		}

		for _, rc := range met.RemediationComponents {
			count += len(rc.Metrics)
		}
	}

	return count
}

func TestAPICNextUsageMetricsBatch(t *testing.T) {
	ctx := t.Context()
	api := getAPIC(t, ctx)

	addMachine(t, ctx, api, "lp1")
	addBouncer(t, ctx, api, "rc1")

	// 4 rows of ~1kB for lp1, then 1 for rc1, then one from a machine that no longer exists
	lpIDs := addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
		usageMetricsPayload("a", 1024),
		usageMetricsPayload("b", 1024),
		usageMetricsPayload("c", 1024),
		usageMetricsPayload("d", 1024),
	)
	rcIDs := addMetrics(t, ctx, api, metric.GeneratedTypeRC, "rc1", time.Now().UTC(), usageMetricsPayload("e", 1024))
	goneIDs := addMetrics(t, ctx, api, metric.GeneratedTypeLP, "deleted", time.Now().UTC(), usageMetricsPayload("f", 1024))

	lps := map[string]*ent.Machine{"lp1": api.dbClient.Ent.Machine.Query().OnlyX(ctx)}
	rcs := map[string]*ent.Bouncer{"rc1": api.dbClient.Ent.Bouncer.Query().OnlyX(ctx)}

	api.usageMetricsBatchBytes = 2500

	batch, err := api.nextUsageMetricsBatch(ctx, 0, lps, rcs)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, lpIDs[:2], batch.ids, "the byte budget cuts the batch short")
	require.Equal(t, lpIDs[1], batch.lastID)
	require.Len(t, batch.metrics.LogProcessors, 1, "rows of the same source are folded into one entry")
	require.Len(t, batch.metrics.LogProcessors[0].Metrics, 2)
	require.Empty(t, batch.metrics.RemediationComponents)

	batch, err = api.nextUsageMetricsBatch(ctx, batch.lastID, lps, rcs)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, lpIDs[2:], batch.ids, "the cursor picks up where the previous batch stopped")

	batch, err = api.nextUsageMetricsBatch(ctx, batch.lastID, lps, rcs)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, append(rcIDs, goneIDs...), batch.ids,
		"rows of a deleted source are settled even though nothing carries them")
	require.Len(t, batch.metrics.RemediationComponents, 1)
	require.Empty(t, batch.metrics.LogProcessors)

	batch, err = api.nextUsageMetricsBatch(ctx, batch.lastID, lps, rcs)
	require.NoError(t, err)
	require.Nil(t, batch, "a nil batch means the backlog is drained")
}

func TestAPICNextUsageMetricsBatchOversizedRow(t *testing.T) {
	ctx := t.Context()
	api := getAPIC(t, ctx)

	addMachine(t, ctx, api, "lp1")

	ids := addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
		usageMetricsPayload("a", 8192),
		usageMetricsPayload("b", 128),
	)

	api.usageMetricsBatchBytes = 1024

	// a row bigger than the whole budget must go out on its own, or it blocks everything behind it
	batch, err := api.nextUsageMetricsBatch(ctx, 0, map[string]*ent.Machine{"lp1": api.dbClient.Ent.Machine.Query().OnlyX(ctx)}, nil)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, ids[:1], batch.ids)

	batch, err = api.nextUsageMetricsBatch(ctx, batch.lastID, map[string]*ent.Machine{"lp1": api.dbClient.Ent.Machine.Query().OnlyX(ctx)}, nil)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, ids[1:], batch.ids)
}

func TestAPICNextUsageMetricsBatchUnparseable(t *testing.T) {
	ctx := t.Context()
	api := getAPIC(t, ctx)

	addMachine(t, ctx, api, "lp1")

	ids := addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(), "not json")

	batch, err := api.nextUsageMetricsBatch(ctx, 0, map[string]*ent.Machine{"lp1": api.dbClient.Ent.Machine.Query().OnlyX(ctx)}, nil)
	require.NoError(t, err)
	require.NotNil(t, batch)
	require.Equal(t, ids, batch.ids, "a row we cannot parse is settled, not retried forever")
	require.Empty(t, batch.metrics.LogProcessors)
}

func TestAPICPushUsageMetrics(t *testing.T) {
	ctx := t.Context()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	t.Run("a backlog over the budget goes out in several requests", func(t *testing.T) {
		api := getAPIC(t, ctx)
		sent := mockCAPI(t, api, http.StatusOK)

		addMachine(t, ctx, api, "lp1")
		addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
			usageMetricsPayload("a", 1024),
			usageMetricsPayload("b", 1024),
			usageMetricsPayload("c", 1024),
			usageMetricsPayload("d", 1024),
			usageMetricsPayload("e", 1024),
			usageMetricsPayload("f", 1024),
		)

		api.usageMetricsBatchBytes = 2500

		httpmock.ZeroCallCounters()
		api.pushUsageMetrics(ctx)

		require.Greater(t, httpmock.GetCallCountInfo()["POST "+usageMetricsURL], 1)
		require.Equal(t, 6, windowCount(*sent), "every window is sent exactly once")
		require.Empty(t, pendingMetrics(t, ctx, api))
		require.NotNil(t, (*sent)[0].Lapi, "the lapi block rides on the first request")
		require.Nil(t, (*sent)[1].Lapi)
	})

	t.Run("nothing pending still reports the lapi", func(t *testing.T) {
		api := getAPIC(t, ctx)
		sent := mockCAPI(t, api, http.StatusOK)

		httpmock.ZeroCallCounters()
		api.pushUsageMetrics(ctx)

		require.Equal(t, 1, httpmock.GetCallCountInfo()["POST "+usageMetricsURL])
		require.Len(t, *sent, 1)
		require.NotNil(t, (*sent)[0].Lapi)
		require.Empty(t, (*sent)[0].LogProcessors)
	})

	t.Run("a refused batch is dropped instead of growing forever", func(t *testing.T) {
		api := getAPIC(t, ctx)
		mockCAPI(t, api, http.StatusUnsupportedMediaType)

		addMachine(t, ctx, api, "lp1")
		addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
			usageMetricsPayload("a", 1024),
			usageMetricsPayload("b", 1024),
			usageMetricsPayload("c", 1024),
			usageMetricsPayload("d", 1024),
		)

		api.usageMetricsBatchBytes = 2500

		httpmock.ZeroCallCounters()
		api.pushUsageMetrics(ctx)

		require.Empty(t, pendingMetrics(t, ctx, api), "refused metrics are settled, not queued again")

		// the next run has nothing left to resend
		calls := httpmock.GetCallCountInfo()["POST "+usageMetricsURL]

		api.pushUsageMetrics(ctx)
		require.Equal(t, calls+1, httpmock.GetCallCountInfo()["POST "+usageMetricsURL])
	})

	t.Run("a retryable failure leaves the backlog alone", func(t *testing.T) {
		for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusUnauthorized} {
			t.Run(http.StatusText(status), func(t *testing.T) {
				api := getAPIC(t, ctx)
				mockCAPI(t, api, status)

				addMachine(t, ctx, api, "lp1")
				ids := addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
					usageMetricsPayload("a", 1024),
					usageMetricsPayload("b", 1024),
					usageMetricsPayload("c", 1024),
					usageMetricsPayload("d", 1024),
				)

				api.usageMetricsBatchBytes = 2500

				httpmock.ZeroCallCounters()
				api.pushUsageMetrics(ctx)

				require.Equal(t, 1, httpmock.GetCallCountInfo()["POST "+usageMetricsURL], "the drain stops at the first failure")
				require.Len(t, pendingMetrics(t, ctx, api), len(ids))

				// once the CAPI is back, the whole backlog goes out
				sent := mockCAPI(t, api, http.StatusOK)
				api.pushUsageMetrics(ctx)

				require.Equal(t, 4, windowCount(*sent))
				require.Empty(t, pendingMetrics(t, ctx, api))
			})
		}
	})

	t.Run("metrics too old to be worth pushing are given up on", func(t *testing.T) {
		api := getAPIC(t, ctx)
		sent := mockCAPI(t, api, http.StatusOK)

		addMachine(t, ctx, api, "lp1")
		addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC().Add(-2*usageMetricsMaxAge),
			usageMetricsPayload("old", 1024))
		addMetrics(t, ctx, api, metric.GeneratedTypeLP, "lp1", time.Now().UTC(),
			usageMetricsPayload("fresh", 1024))

		httpmock.ZeroCallCounters()
		api.pushUsageMetrics(ctx)

		require.Equal(t, 1, windowCount(*sent), "only the fresh window is sent")
		require.Empty(t, pendingMetrics(t, ctx, api), "the stale one stops being pending")
	})
}

func TestUsageMetricsBatchRefused(t *testing.T) {
	tests := []struct {
		code    int
		refused bool
	}{
		{http.StatusOK, false},
		{http.StatusBadRequest, true},
		{http.StatusRequestEntityTooLarge, true},
		{http.StatusUnsupportedMediaType, true},
		{http.StatusUnprocessableEntity, true},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusRequestTimeout, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.code), func(t *testing.T) {
			require.Equal(t, tc.refused, usageMetricsBatchRefused(tc.code))
		})
	}
}
