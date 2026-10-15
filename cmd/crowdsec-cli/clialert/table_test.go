package clialert

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

//nolint:gosmopolitan // The renderer uses the process timezone, which these nonparallel tests control.
func TestAlertsTableLocalTime(t *testing.T) {
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
				ID:       1,
				Scenario: new("example"),
				StartAt:  new(tt.timestamp),
				Source: &models.Source{
					Scope: new("ip"),
					Value: new("192.0.2.1"),
				},
			}}

			// Capture the human-readable table to verify its timestamp presentation.
			var output bytes.Buffer
			alertsTable(&output, "no", &alerts, false)

			require.Contains(t, output.String(), tt.want)
			require.Equal(t, tt.timestamp, *alerts[0].StartAt)
		})
	}
}
