package clialert

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
)

//nolint:gosmopolitan // The renderer uses the process timezone, which these nonparallel tests control.
func TestAlertHumanTimestamps(t *testing.T) {
	tests := []struct {
		name      string
		zone      string
		timestamp string
		want      string
	}{
		{
			name: "UTC", zone: "UTC",
			timestamp: "2026-01-15T12:34:56Z", want: "2026-01-15T12:34:56Z",
		},
		{
			name: "positive offset and date rollover", zone: "Asia/Tokyo",
			timestamp: "2026-01-15T20:34:56Z", want: "2026-01-16T05:34:56+09:00",
		},
		{
			name: "winter", zone: "America/New_York",
			timestamp: "2026-01-15T12:34:56Z", want: "2026-01-15T07:34:56-05:00",
		},
		{
			name: "summer", zone: "America/New_York",
			timestamp: "2026-07-15T12:34:56Z", want: "2026-07-15T08:34:56-04:00",
		},
		{
			name: "offset input and fractional seconds", zone: "Europe/Paris",
			timestamp: "2026-07-15T12:34:56.123456789-04:00", want: "2026-07-15T18:34:56.123456789+02:00",
		},
		{
			name: "invalid timestamp", zone: "Europe/Paris",
			timestamp: "invalid", want: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			location, err := time.LoadLocation(tt.zone)
			require.NoError(t, err)

			// Exercise process-local formatting without leaking the zone between tests.
			previousLocation := time.Local
			time.Local = location
			t.Cleanup(func() { time.Local = previousLocation })

			alerts := models.GetAlertsResponse{{
				ID:        1,
				Scenario:  new("example"),
				CreatedAt: tt.timestamp,
				StartAt:   new(tt.timestamp),
				StopAt:    new(tt.timestamp),
				Events:    []*models.Event{{Timestamp: new(tt.timestamp)}},
				Decisions: []*models.Decision{{Scope: new("ip"), Value: new("192.0.2.1"), Type: new("ban"), Duration: new("1h"), Simulated: new(false)}},
				Source: &models.Source{
					Scope: new("ip"),
					Value: new("192.0.2.1"),
				},
			}}

			// Capture the human-readable table to verify its timestamp presentation.
			var output bytes.Buffer
			alertsTable(&output, "no", &alerts, false)

			require.Contains(t, output.String(), tt.want)

			output.Reset()
			cli := New(func() *csconfig.Config { return &csconfig.Config{Cscli: &csconfig.CscliCfg{Color: "no"}} })
			require.NoError(t, cli.displayOneAlert(&output, alerts[0], true))
			require.Equal(t, 5, strings.Count(output.String(), tt.want), output.String())
		})
	}
}
