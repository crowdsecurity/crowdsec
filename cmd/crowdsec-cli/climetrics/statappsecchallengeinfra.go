package climetrics

import (
	"fmt"
	"io"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
)

// statAppsecChallengeInfra holds the process-global housekeeping counters of
// the bot-detection challenge runtime (key rotation, obfuscation, cache
// eviction). Unlike the lifecycle funnel these carry no appsec_engine label
// — the challenge runtime is a single per-process instance shared by every
// engine — so this is a flat metric -> count map rather than per-engine.
type statAppsecChallengeInfra map[string]int

func (statAppsecChallengeInfra) Description() (string, string) {
	return "Bot Detection Infrastructure Metrics",
		`Tracks the internal upkeep of the AppSec challenge runtime: signing-key rotation, JS re-obfuscation and cache eviction.`
}

func (s statAppsecChallengeInfra) Process(metric string, val int) {
	s[metric] += val
}

// infraRow pairs a metric key with the label shown in the table, in a fixed
// order so the rendered output is stable across runs.
var infraRows = []struct {
	key   string
	label string
}{
	{"kepoch_generated", "Signing key regenerated"},
	{"kepoch_evicted", "Signing key evicted"},
	{"reobfuscation_dynamic", "Re-obfuscation (dynamic module)"},
	{"reobfuscation_library", "Re-obfuscation (library bundle)"},
	{"dynamic_module_evicted", "Dynamic module evicted"},
}

func (s statAppsecChallengeInfra) Table(out io.Writer, wantColor string, noUnit bool, showEmpty bool) {
	t := cstable.New(out, wantColor).Writer
	t.AppendHeader(table.Row{"Metric", "Count"})

	numRows := 0
	for _, r := range infraRows {
		val, ok := s[r.key]
		if !ok {
			continue
		}
		t.AppendRow(table.Row{r.label, formatNumber(int64(val), !noUnit)})
		numRows++
	}

	if numRows == 0 && !showEmpty {
		return
	}

	title, _ := s.Description()
	t.SetTitle(title)
	fmt.Fprintln(out, t.Render())
}
