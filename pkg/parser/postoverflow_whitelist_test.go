package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// makeOverflow builds an OVFLW event close to what leakybucket.NewAlert emits:
// a single Ip-scoped source and the convenience Alert pointer. reprocess mirrors
// a scenario with `reprocess: true`.
func makeOverflow(ip string, reprocess bool) pipeline.Event {
	scenario := "test/scenario"
	scope := "Ip"
	val := ip
	src := models.Source{IP: ip, Scope: &scope, Value: &val}
	ra := pipeline.RuntimeAlert{
		Reprocess: reprocess,
		Sources:   map[string]models.Source{ip: src},
		APIAlerts: []models.Alert{{Scenario: &scenario, Source: &src}},
	}
	ra.Alert = &ra.APIAlerts[0]

	return pipeline.Event{Type: pipeline.OVFLW, Overflow: ra}
}

func writeStage(t *testing.T, dir, file, body string) string {
	t.Helper()
	path := filepath.Join(dir, file)
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	return path
}

// This is the exact call runOutput makes (cmd/crowdsec/output.go): it runs the
// postoverflow nodes on the overflow, then reads event.Overflow.Whitelisted.
func runPostOverflow(t *testing.T, pctx *UnixParserCtx, nodes []Node, evt pipeline.Event) pipeline.Event {
	t.Helper()
	out, err := Parse(*pctx, evt, nodes, nil)
	require.NoError(t, err)

	return out
}

// A plain postoverflow CIDR whitelist must apply to overflows regardless of the
// scenario's `reprocess` flag: reprocess only changes what runOutput does *after*
// the whitelist verdict, never the verdict itself.
func TestPostOverflowWhitelist_ReprocessAgnostic(t *testing.T) {
	pctx, ectx := prepTests(t)

	dir := t.TempDir()
	wl := writeStage(t, dir, "whitelist.yaml", `
name: test/povfw-whitelist
filter: "evt.Overflow.Alert != nil"
whitelist:
  reason: test
  cidr:
    - 1.2.3.0/24
`)

	nodes, err := LoadStages([]Stagefile{{Filename: wl, Stage: "s01-whitelist"}}, pctx, ectx)
	require.NoError(t, err)

	for _, reprocess := range []bool{false, true} {
		out := runPostOverflow(t, pctx, nodes, makeOverflow("1.2.3.4", reprocess))
		require.Truef(t, out.Overflow.Whitelisted, "reprocess=%v: overflow should be whitelisted", reprocess)
	}
}

// Regression: the postoverflow whitelist lives in s01-whitelist, but Parse aborts
// a stage early when no node in an *earlier* stage "passes" (runtime.go). So if
// the s00-enrich stage produces no passing node for a given overflow, s01-whitelist
// is never reached and a source that should be whitelisted is alerted/banned.
func TestPostOverflowWhitelist_SkippedWhenEnrichStageDoesNotPass(t *testing.T) {
	pctx, ectx := prepTests(t)

	dir := t.TempDir()
	// s00-enrich node whose filter never matches this overflow, so the stage has
	// no passing node. Mirrors e.g. an rdns enricher gated on remediation==true
	// being the only node in the enrich stage.
	enrich := writeStage(t, dir, "enrich.yaml", `
name: test/povfw-enrich
onsuccess: next_stage
filter: "evt.Overflow.Alert.Remediation == true"
statics:
  - meta: enriched_here
    value: "yes"
`)
	wl := writeStage(t, dir, "whitelist.yaml", `
name: test/povfw-whitelist
filter: "evt.Overflow.Alert != nil"
whitelist:
  reason: test
  cidr:
    - 1.2.3.0/24
`)

	nodes, err := LoadStages([]Stagefile{
		{Filename: enrich, Stage: "s00-enrich"},
		{Filename: wl, Stage: "s01-whitelist"},
	}, pctx, ectx)
	require.NoError(t, err)

	out := runPostOverflow(t, pctx, nodes, makeOverflow("1.2.3.4", true))
	require.True(t, out.Overflow.Whitelisted,
		"source 1.2.3.4 matches the s01-whitelist CIDR but the whitelist was skipped because s00-enrich did not pass")
}
