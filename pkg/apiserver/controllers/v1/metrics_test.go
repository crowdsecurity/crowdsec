package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

// histogramCountsByEndpoint returns the sample count of each
// cs_lapi_request_duration_seconds series, keyed by endpoint label.
func histogramCountsByEndpoint(t *testing.T) map[string]uint64 {
	t.Helper()

	ch := make(chan prometheus.Metric, 16)

	go func() {
		metrics.LapiResponseTime.Collect(ch)
		close(ch)
	}()

	counts := map[string]uint64{}

	for m := range ch {
		var pb dto.Metric
		require.NoError(t, m.Write(&pb))

		endpoint := ""
		found := false

		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "endpoint" {
				endpoint = lp.GetValue()
				found = true
			}
		}

		require.True(t, found, "histogram series without endpoint label")
		counts[endpoint] += pb.GetHistogram().GetSampleCount()
	}

	return counts
}

func TestPrometheusMiddlewareRouteLabels(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(PrometheusMiddleware)
	router.GET("/v1/decisions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	tests := []struct {
		name         string
		path         string
		wantRoute    string
		wantEndpoint string
	}{
		{
			name:         "matched route keeps its pattern",
			path:         "/v1/decisions",
			wantRoute:    "/v1/decisions",
			wantEndpoint: "/v1/decisions",
		},
		{
			// e.g. a browser requesting /favicon.ico, or a scanner
			// probing random paths: the raw path must not become a
			// metric label, it collapses into "invalid-endpoint".
			name:         "unmatched route is invalid-endpoint",
			path:         "/favicon.ico",
			wantRoute:    "invalid-endpoint",
			wantEndpoint: "invalid-endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routeHitsBefore := testutil.ToFloat64(metrics.LapiRouteHits.WithLabelValues(tt.wantRoute, http.MethodGet))
			endpointCountsBefore := histogramCountsByEndpoint(t)

			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			require.InDelta(t, routeHitsBefore+1, testutil.ToFloat64(metrics.LapiRouteHits.WithLabelValues(tt.wantRoute, http.MethodGet)), 0)
			require.Equal(t, endpointCountsBefore[tt.wantEndpoint]+1, histogramCountsByEndpoint(t)[tt.wantEndpoint])

			_, emptyEndpoint := histogramCountsByEndpoint(t)[""]
			require.False(t, emptyEndpoint, "no histogram series should carry an empty endpoint label")
		})
	}
}
