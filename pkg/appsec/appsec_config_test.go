package appsec

import (
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// Verify that rules from phase sections are moved to flat fields
	// and the phase section's Rules field is cleared
	cfg := newTestConfig()
	f := writeTempYAML(t, `
name: test-normalize
inband:
  rules:
    - ruleA
    - ruleB
outofband:
  rules:
    - ruleC
`)

	require.NoError(t, cfg.LoadByPath(f))
	assert.Equal(t, []string{"ruleA", "ruleB"}, cfg.InBandRules)
	assert.Equal(t, []string{"ruleC"}, cfg.OutOfBandRules)
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
