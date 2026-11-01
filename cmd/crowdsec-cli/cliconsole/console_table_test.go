package cliconsole

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/consolestatus"
)

//nolint:gosmopolitan // Exercise the CLI's process-local display timezone.
func TestConsoleLastOrderLocalTime(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	require.NoError(t, err)
	// Restore the process timezone after this nonparallel test.
	previousLocation := time.Local
	time.Local = location
	t.Cleanup(func() { time.Local = previousLocation })

	for _, tt := range []struct{ timestamp, want string }{
		{"2026-07-15T12:34:56Z", "2026-07-15T14:34:56+02:00"},
		{"never", "never"},
	} {
		t.Run(tt.timestamp, func(t *testing.T) {
			var output bytes.Buffer
			cmdConsoleConnectionTable(&output, "no", liveConsoleStatus{
				registered: true,
				reachable:  true,
				capi:       consolestatus.CAPIStatus{Enrolled: true},
				papi:       &consolestatus.PAPIInfo{LastOrder: tt.timestamp},
			})
			require.Contains(t, output.String(), tt.want)
		})
	}
}
