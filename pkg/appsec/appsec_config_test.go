package appsec

import (
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
)

func newTestConfig() AppsecConfig {
	return AppsecConfig{
		Logger: log.NewEntry(log.StandardLogger()),
	}
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()

	f := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(f, []byte(content), 0o644))

	return f
}

func TestLoadByPathNewFormatInband(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-config
inband:
  rules:
    - crowdsecurity/vpatch-*
  on_match:
    - apply:
        - SetReturnCode(413)
  pre_eval:
    - filter: "1==1"
      apply:
        - RemoveInBandRuleByID(123)
  post_eval:
    - apply:
        - DumpRequest()
  options:
    disable_body_inspection: true
  variables_tracking:
    - tx.anomaly_score
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.Equal(t, "test-config", cfg.Name)
	assert.Equal(t, []string{"crowdsecurity/vpatch-*"}, cfg.InBandRules)
	assert.True(t, cfg.InbandOptions.DisableBodyInspection)
	assert.Contains(t, cfg.VariablesTracking, "tx.anomaly_score")

	// Hooks should be in the InBand phase config
	require.NotNil(t, cfg.InBand)
	assert.Len(t, cfg.InBand.OnMatch, 1)
	assert.Len(t, cfg.InBand.PreEval, 1)
	assert.Len(t, cfg.InBand.PostEval, 1)

	// Top-level hook lists should be empty (hooks are phase-scoped)
	assert.Empty(t, cfg.OnMatch)
	assert.Empty(t, cfg.PreEval)
	assert.Empty(t, cfg.PostEval)
}

func TestLoadByPathNewFormatOutofband(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-outofband
outofband:
  rules:
    - crowdsecurity/experimental-*
  on_match:
    - apply:
        - CancelAlert()
  options:
    request_body_in_memory_limit: 1048576
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.Equal(t, []string{"crowdsecurity/experimental-*"}, cfg.OutOfBandRules)
	require.NotNil(t, cfg.OutOfBandOptions.RequestBodyInMemoryLimit)
	assert.Equal(t, 1048576, *cfg.OutOfBandOptions.RequestBodyInMemoryLimit)

	require.NotNil(t, cfg.OutOfBand)
	assert.Len(t, cfg.OutOfBand.OnMatch, 1)
}

func TestLoadByPathOldFormat(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-old
inband_rules:
  - crowdsecurity/vpatch-*
outofband_rules:
  - crowdsecurity/experimental-*
on_match:
  - filter: "IsInBand == true"
    apply:
      - SetReturnCode(413)
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.Equal(t, []string{"crowdsecurity/vpatch-*"}, cfg.InBandRules)
	assert.Equal(t, []string{"crowdsecurity/experimental-*"}, cfg.OutOfBandRules)
	assert.Len(t, cfg.OnMatch, 1)
	assert.Nil(t, cfg.InBand)
	assert.Nil(t, cfg.OutOfBand)
}

func TestLoadByPathMixedFormat(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-mixed
inband_rules:
  - crowdsecurity/base-config
on_match:
  - filter: "IsInBand == true"
    apply:
      - SendAlert()
inband:
  rules:
    - crowdsecurity/vpatch-*
  on_match:
    - apply:
        - SetReturnCode(413)
`)

	require.NoError(t, cfg.LoadByPath(f))
	// Rules should be merged
	assert.Equal(t, []string{"crowdsecurity/base-config", "crowdsecurity/vpatch-*"}, cfg.InBandRules)
	// Shared hook stays in shared list
	assert.Len(t, cfg.OnMatch, 1)
	// Phase-scoped hook in phase config
	require.NotNil(t, cfg.InBand)
	assert.Len(t, cfg.InBand.OnMatch, 1)
}

func TestLoadByPathOnLoadUnderPhaseRejected(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-bad
inband:
  on_load:
    - apply:
        - RemoveInBandRuleByID(123)
`)

	err := cfg.LoadByPath(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "on_load")
}

func TestLoadByPathMultiFileLoading(t *testing.T) {
	cfg := newTestConfig()

	// First file: old format
	f1 := writeTempYAML(t, `
name: test-multi
inband_rules:
  - crowdsecurity/base-config
on_match:
  - filter: "IsInBand == true"
    apply:
      - SendAlert()
`)

	// Second file: new format
	dir := t.TempDir()
	f2 := filepath.Join(dir, "config2.yaml")
	require.NoError(t, os.WriteFile(f2, []byte(`
inband:
  rules:
    - crowdsecurity/vpatch-*
  on_match:
    - apply:
        - SetReturnCode(413)
`), 0o644))

	require.NoError(t, cfg.LoadByPath(f1))
	require.NoError(t, cfg.LoadByPath(f2))

	// Rules merged from both files
	assert.Equal(t, []string{"crowdsecurity/base-config", "crowdsecurity/vpatch-*"}, cfg.InBandRules)
	// Shared hook from file 1
	assert.Len(t, cfg.OnMatch, 1)
	// Phase-scoped hook from file 2
	require.NotNil(t, cfg.InBand)
	assert.Len(t, cfg.InBand.OnMatch, 1)
}

func TestLoadByPathPhaseOptionsOverride(t *testing.T) {
	cfg := newTestConfig()

	// Phase section options should override top-level options
	f := writeTempYAML(t, `
name: test-opts
inband_options:
  disable_body_inspection: false
inband:
  options:
    disable_body_inspection: true
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.True(t, cfg.InbandOptions.DisableBodyInspection)
}

func TestLoadByPathPhaseRulesNormalized(t *testing.T) {
	// Verify that rules and variables_tracking from phase sections are moved
	// to flat fields, and the phase section's fields are cleared afterward.
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-normalize
inband:
  rules:
    - ruleA
    - ruleB
  variables_tracking:
    - tx.anomaly_score
outofband:
  rules:
    - ruleC
`)

	require.NoError(t, cfg.LoadByPath(f))

	// Rules moved to flat fields
	assert.Equal(t, []string{"ruleA", "ruleB"}, cfg.InBandRules)
	assert.Equal(t, []string{"ruleC"}, cfg.OutOfBandRules)

	// Phase config objects survive (they may still hold hooks)
	require.NotNil(t, cfg.InBand)
	require.NotNil(t, cfg.OutOfBand)

	// Rules cleared from phase sections after normalization
	assert.Nil(t, cfg.InBand.Rules)
	assert.Nil(t, cfg.OutOfBand.Rules)

	// variables_tracking also normalized
	assert.Contains(t, cfg.VariablesTracking, "tx.anomaly_score")
	assert.Nil(t, cfg.InBand.VariablesTracking)
}

func TestLoadByPathEmptyPhaseSection(t *testing.T) {
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-empty-phase
inband:
  rules: []
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.Empty(t, cfg.InBandRules)
}

func TestBuildPopulatesPhaseHooks(t *testing.T) {
	cfg := AppsecConfig{
		Logger:             log.NewEntry(log.StandardLogger()),
		DefaultRemediation: "ban",
		// Shared hooks
		PreEval:  []Hook{{Apply: []string{"SetRemediationByTag('foo', 'captcha')"}}},
		PostEval: []Hook{{Apply: []string{"DumpRequest()"}}},
		OnMatch:  []Hook{{Apply: []string{"SetReturnCode(418)"}}},
		// InBand hooks
		InBand: &AppsecPhaseConfig{
			PreEval: []Hook{{Apply: []string{"SetRemediationByTag('bar', 'ban')"}}},
			OnMatch: []Hook{{Apply: []string{"SetReturnCode(413)"}}},
		},
		// OutOfBand hooks
		OutOfBand: &AppsecPhaseConfig{
			PostEval: []Hook{{Apply: []string{"DumpRequest()"}}},
		},
	}

	hub := &cwhub.Hub{}
	rt, err := cfg.Build(t.Context(), hub)
	require.NoError(t, err)

	// Common hooks populated
	assert.Len(t, rt.CommonHooks.PreEval, 1)
	assert.Len(t, rt.CommonHooks.PostEval, 1)
	assert.Len(t, rt.CommonHooks.OnMatch, 1)

	// InBand hooks populated
	assert.Len(t, rt.InBandHooks.PreEval, 1)
	assert.Empty(t, rt.InBandHooks.PostEval)
	assert.Len(t, rt.InBandHooks.OnMatch, 1)

	// OutOfBand hooks populated
	assert.Empty(t, rt.OutOfBandHooks.PreEval)
	assert.Len(t, rt.OutOfBandHooks.PostEval, 1)
	assert.Empty(t, rt.OutOfBandHooks.OnMatch)

	// Expressions are actually compiled
	assert.NotNil(t, rt.CommonHooks.PreEval[0].ApplyExpr)
	assert.NotNil(t, rt.InBandHooks.OnMatch[0].ApplyExpr)
}

func TestBuildNilPhaseConfig(t *testing.T) {
	cfg := AppsecConfig{
		Logger:             log.NewEntry(log.StandardLogger()),
		DefaultRemediation: "ban",
		OnMatch:            []Hook{{Apply: []string{"SetReturnCode(418)"}}},
		// InBand and OutOfBand left nil
	}

	hub := &cwhub.Hub{}
	rt, err := cfg.Build(t.Context(), hub)
	require.NoError(t, err)

	// Common hooks populated
	assert.Len(t, rt.CommonHooks.OnMatch, 1)

	// Phase-specific hooks empty (zero-value PhaseHooks)
	assert.Empty(t, rt.InBandHooks.PreEval)
	assert.Empty(t, rt.InBandHooks.PostEval)
	assert.Empty(t, rt.InBandHooks.OnMatch)
	assert.Empty(t, rt.OutOfBandHooks.PreEval)
	assert.Empty(t, rt.OutOfBandHooks.PostEval)
	assert.Empty(t, rt.OutOfBandHooks.OnMatch)
}

func TestBuildOnLoadStaysOutOfPhaseHooks(t *testing.T) {
	cfg := AppsecConfig{
		Logger:             log.NewEntry(log.StandardLogger()),
		DefaultRemediation: "ban",
		OnLoad:             []Hook{{Apply: []string{"RemoveInBandRuleByID(123)"}}},
	}

	hub := &cwhub.Hub{}
	rt, err := cfg.Build(t.Context(), hub)
	require.NoError(t, err)

	assert.Len(t, rt.CompiledOnLoad, 1)
	assert.NotNil(t, rt.CompiledOnLoad[0].ApplyExpr)

	// PhaseHooks should have no on_load contamination
	assert.Empty(t, rt.CommonHooks.PreEval)
	assert.Empty(t, rt.CommonHooks.PostEval)
	assert.Empty(t, rt.CommonHooks.OnMatch)
}
