package climachine

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

//nolint:gosmopolitan // Exercise local display while duration arithmetic uses absolute instants.
func TestMachineTimestamps(t *testing.T) {
	location, err := time.LoadLocation("Europe/Paris")
	require.NoError(t, err)
	// Restore process-wide presentation settings after this nonparallel test.
	previousLocation, previousOutput := time.Local, color.Output
	time.Local = location
	t.Cleanup(func() { time.Local, color.Output = previousLocation, previousOutput })

	cfg := &csconfig.Config{Cscli: &csconfig.CscliCfg{Color: "no"}}
	cli := New(func() *csconfig.Config { return cfg })
	at := time.Date(2026, time.July, 15, 12, 34, 56, 0, time.UTC)

	for _, format := range []string{"list", "inspect", "json", "raw"} {
		t.Run(format, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				heartbeat := time.Now().UTC().Add(-90 * time.Second)
				machine := &ent.Machine{MachineId: "example", CreatedAt: at, UpdatedAt: at.Add(time.Hour), LastHeartbeat: new(heartbeat)}
				var output bytes.Buffer
				color.Output = &output
				switch format {
				case "list":
					cli.listHuman(&output, ent.Machines{machine})
					require.Contains(t, output.String(), "2026-07-15T15:34:56+02:00")
					require.Contains(t, output.String(), "1m30s")
				case "inspect":
					cli.inspectHuman(&output, machine)
					require.Contains(t, output.String(), "2026-07-15 14:34:56 +0200 CEST")
					require.Contains(t, output.String(), "2026-07-15 15:34:56 +0200 CEST")
					require.Contains(t, output.String(), heartbeat.In(location).String())
				case "json":
					cfg.Cscli.Output = "json"
					require.NoError(t, cli.inspect(machine, nil))
					require.Contains(t, output.String(), `"created_at": "2026-07-15T12:34:56Z"`)
					require.Contains(t, output.String(), heartbeat.Format(time.RFC3339))
				case "raw":
					require.NoError(t, cli.listCSV(&output, ent.Machines{machine}))
					require.Contains(t, output.String(), "2026-07-15T13:34:56Z")
					require.Contains(t, output.String(), heartbeat.Format(time.RFC3339))
				}
				elapsed, active := getLastHeartbeat(machine)
				require.Equal(t, "1m30s", elapsed)
				require.True(t, active)
			})
		})
	}

	t.Run("expired heartbeat", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			machine := &ent.Machine{LastHeartbeat: new(time.Now().UTC().Add(-3 * time.Minute))}
			elapsed, active := getLastHeartbeat(machine)
			require.Equal(t, "3m0s", elapsed)
			require.False(t, active)
		})
	})

	t.Run("missing heartbeat", func(t *testing.T) {
		machine := &ent.Machine{CreatedAt: at, UpdatedAt: at}
		var output bytes.Buffer
		cli.inspectHuman(&output, machine)
		require.Contains(t, output.String(), "<nil>")
		elapsed, active := getLastHeartbeat(machine)
		require.Equal(t, "-", elapsed)
		require.False(t, active)
	})
}
