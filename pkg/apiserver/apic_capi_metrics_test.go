package apiserver

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/modelscapi"
)

func capiErrors(operation string) float64 {
	return testutil.ToFloat64(metrics.CapiErrors.WithLabelValues(operation))
}

func TestAPICPullTopMetrics(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		wantPulled bool
	}{
		{"successful pull", http.StatusOK, true},
		{"unauthorized", http.StatusUnauthorized, false},
		{"forbidden", http.StatusForbidden, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			api := getAPIC(t, ctx)

			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			httpmock.RegisterResponder("GET", "http://api.crowdsec.net/api/decisions/stream",
				httpmock.NewBytesResponder(tc.status, jsonMarshalX(modelscapi.GetDecisionsStreamResponse{})))

			apiURL, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)

			api.apiClient, err = apiclient.NewDefaultClient(apiURL, "/api", "", nil)
			require.NoError(t, err)

			metrics.CapiLastPullTimestamp.Set(0)

			errorsBefore := capiErrors(metrics.CapiOperationPull)

			err = api.PullTop(ctx, true)

			lastPull := testutil.ToFloat64(metrics.CapiLastPullTimestamp)

			if tc.wantPulled {
				require.NoError(t, err)
				require.InDelta(t, float64(time.Now().Unix()), lastPull, 5)
				require.InDelta(t, errorsBefore, capiErrors(metrics.CapiOperationPull), 0)

				return
			}

			require.Error(t, err)
			require.InDelta(t, 0, lastPull, 0, "a failed pull must not look fresh")
			require.InDelta(t, errorsBefore+1, capiErrors(metrics.CapiOperationPull), 0)
		})
	}
}

func TestAPICPushErrorsMetric(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr float64
	}{
		{"accepted", http.StatusOK, 0},
		{"rejected", http.StatusInternalServerError, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			api := getAPIC(t, ctx)

			httpmock.Activate()
			defer httpmock.DeactivateAndReset()

			httpmock.RegisterResponder("POST", "http://api.crowdsec.net/api/signals",
				httpmock.NewBytesResponder(tc.status, []byte("{}")))

			apiURL, err := url.ParseRequestURI("http://api.crowdsec.net/")
			require.NoError(t, err)

			api.apiClient, err = apiclient.NewDefaultClient(apiURL, "/api", "", nil)
			require.NoError(t, err)

			before := capiErrors(metrics.CapiOperationPush)

			err = api.sendBatch(ctx, nil)
			require.Equal(t, tc.wantErr > 0, err != nil)
			require.InDelta(t, before+tc.wantErr, capiErrors(metrics.CapiOperationPush), 0)
		})
	}
}

func TestAPICUsageMetricsErrorsMetric(t *testing.T) {
	ctx := t.Context()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	for _, tc := range []struct {
		name    string
		status  int
		wantErr float64
	}{
		{"accepted", http.StatusOK, 0},
		{"rejected", http.StatusInternalServerError, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := getAPIC(t, ctx)
			mockCAPI(t, api, tc.status)

			before := capiErrors(metrics.CapiOperationMetrics)

			api.pushUsageMetrics(ctx)

			require.InDelta(t, before+tc.wantErr, capiErrors(metrics.CapiOperationMetrics), 0)
		})
	}
}
