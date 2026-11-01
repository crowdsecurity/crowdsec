package clibouncer

import (
	"bytes"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

//nolint:gosmopolitan // Exercise the CLI's process-local display timezone.
func TestBouncerTimestamps(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	require.NoError(t, err)
	// Restore process-wide presentation settings after this nonparallel test.
	previousLocation, previousOutput := time.Local, color.Output
	time.Local = location
	t.Cleanup(func() { time.Local, color.Output = previousLocation, previousOutput })

	cfg := &csconfig.Config{Cscli: &csconfig.CscliCfg{Color: "no"}}
	cli := New(func() *csconfig.Config { return cfg })
	at := time.Date(2026, time.July, 15, 12, 34, 56, 0, time.UTC)
	bouncer := &ent.Bouncer{Name: "example", CreatedAt: at, UpdatedAt: at.Add(time.Hour), LastPull: new(at.Add(2 * time.Hour))}

	for _, format := range []string{"list", "inspect", "json", "raw"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			color.Output = &output
			switch format {
			case "list":
				cli.listHuman(&output, ent.Bouncers{bouncer})
				require.Contains(t, output.String(), "2026-07-15T16:34:56+02:00")
			case "inspect":
				cli.inspectHuman(&output, bouncer)
				for _, hour := range []string{"14", "15", "16"} {
					require.Contains(t, output.String(), "2026-07-15 "+hour+":34:56 +0200 CEST")
				}
			case "json":
				cfg.Cscli.Output = "json"
				require.NoError(t, cli.inspect(bouncer))
				require.Contains(t, output.String(), `"created_at": "2026-07-15T12:34:56Z"`)
				require.Contains(t, output.String(), `"last_pull": "2026-07-15T14:34:56Z"`)
			case "raw":
				require.NoError(t, cli.listCSV(&output, ent.Bouncers{bouncer}))
				require.Contains(t, output.String(), "2026-07-15T14:34:56Z")
			}
		})
	}

}
