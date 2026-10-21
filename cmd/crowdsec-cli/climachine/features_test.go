package climachine

import (
	"bytes"
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent"
)

func TestMachineFeatures(t *testing.T) {
	previousOutput := color.Output
	t.Cleanup(func() { color.Output = previousOutput })

	tests := []struct {
		name     string
		features []string
		list     string
		inspect  []string
		json     string
		raw      string
	}{
		{
			name:     "with features",
			features: []string{"bot_detection", "log_processor", "waf"},
			list:     "bot_detection,log_processor,waf",
			inspect:  []string{"bot_detection", "log_processor", "waf"},
			json:     `"features": [`,
			raw:      `,"bot_detection,log_processor,waf"` + "\n",
		},
		{
			// reported by a log processor that predates features
			name: "no features",
			raw:  ",/,\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &csconfig.Config{Cscli: &csconfig.CscliCfg{Color: "no"}}
			cli := New(func() *csconfig.Config { return cfg })
			machine := &ent.Machine{MachineId: "example", Features: tc.features}

			var output bytes.Buffer

			cli.listHuman(&output, ent.Machines{machine})
			require.Contains(t, output.String(), "Features")

			if tc.list != "" {
				require.Contains(t, output.String(), tc.list)
			}

			output.Reset()
			cli.inspectHuman(&output, machine)

			if len(tc.inspect) == 0 {
				require.NotContains(t, output.String(), "Features")
			}

			for _, feature := range tc.inspect {
				require.Contains(t, output.String(), "| "+feature+" ")
			}

			color.Output = &output
			cfg.Cscli.Output = "json"

			output.Reset()
			require.NoError(t, cli.listCSV(&output, ent.Machines{machine}))
			require.True(t, strings.HasPrefix(output.String(), "machine_id,ip_address,updated_at,validated,version,auth_type,last_heartbeat,os,features\n"))
			require.True(t, strings.HasSuffix(output.String(), tc.raw), output.String())

			output.Reset()
			require.NoError(t, cli.inspect(machine, nil))

			if tc.json != "" {
				require.Contains(t, output.String(), tc.json)
			} else {
				require.NotContains(t, output.String(), `"features"`)
			}
		})
	}
}
