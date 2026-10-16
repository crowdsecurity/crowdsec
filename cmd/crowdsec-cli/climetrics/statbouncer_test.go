package climetrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

//nolint:gosmopolitan // Cover the repeated local hour at the end of daylight saving time.
func TestBouncerMetricsLocalTime(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	require.NoError(t, err)
	// Restore the process timezone after this nonparallel test.
	previousLocation := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previousLocation })

	first := time.Date(2026, time.November, 1, 5, 30, 0, 0, time.UTC)
	payload := fmt.Sprintf(`{"metrics":[
		{"meta":{"utc_now_timestamp":%d},"items":[{"name":"dropped","unit":"byte","value":3,"labels":{"origin":"cscli"}}]},
		{"meta":{"utc_now_timestamp":%d},"items":[{"name":"dropped","unit":"byte","value":4,"labels":{"origin":"cscli"}}]}]}`,
		first.Unix(), first.Add(time.Hour).Unix())
	s := &statBouncer{}
	raw, oldest := s.extractRawMetrics([]*ent.Metric{{GeneratedBy: "example", Payload: payload}})
	require.Len(t, raw, 2)
	s.oldestTS = oldest
	s.aggOverIPType = s.newAggregationOverIPType(s.newAggregationOverTime(raw))
	s.aggOverOrigin = s.newAggregationOverOrigin(s.aggOverIPType)

	var output bytes.Buffer
	s.Table(&output, "no", true, true)
	text := strings.NewReplacer("|", "", "\n", "", " ", "").Replace(output.String())
	require.Contains(t, text, "since2026-11-0101:30:00-0400EDT")
	require.Equal(t, time.Hour, raw[1].collectedAt.Sub(raw[0].collectedAt))
	encoded, err := json.Marshal(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"example":{"cscli":{"dropped":{"byte":7}}}}`, string(encoded))
}
