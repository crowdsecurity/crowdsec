package apiserver

import (
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
)

func TestHeartBeat(t *testing.T) {
	ctx := t.Context()
	lapi := SetupLAPITest(t, ctx)

	w := lapi.RecordResponse(t, ctx, http.MethodGet, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 200, w.Code)

	got := testutil.ToFloat64(metrics.GlobalMachinesLastHeartbeatTimestamp.With(prometheus.Labels{"machine": "test"}))
	assert.InDelta(t, float64(time.Now().Unix()), got, 5.0)

	w = lapi.RecordResponse(t, ctx, http.MethodPost, "/v1/heartbeat", emptyBody, "password")
	assert.Equal(t, 405, w.Code)
}
