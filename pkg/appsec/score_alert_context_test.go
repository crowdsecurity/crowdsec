package appsec

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/alertcontext"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// loadContextYAML drives the real console/context.yaml path — file on disk,
// LoadConsoleContext, NewAlertContext — rather than handing the expressions
// straight to the compiler, so a change to the loader or the file format
// shows up here too.
func loadContextYAML(t *testing.T, body string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "context.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg := &csconfig.Config{
		Crowdsec:    &csconfig.CrowdsecServiceCfg{ConsoleContextPath: path},
		ConfigPaths: &csconfig.ConfigurationPaths{},
	}
	require.NoError(t, alertcontext.LoadConsoleContext(cfg, nil))
	require.NoError(t, alertcontext.NewAlertContext(cfg.Crowdsec.ContextToSend, alertcontext.MaxContextValueLen))
}

// The sibling helper in challenge_alert_test.go works off a built alert;
// these tests call the context builders directly, on both entry points.
func contextMap(metas []*models.MetaItems0) map[string]string {
	out := make(map[string]string, len(metas))
	for _, m := range metas {
		out[m.Key] = m.Value
	}

	return out
}

// One grouped and one ungrouped signal: the category breakdown lists both,
// the second under its own label, so the parts still add up to the total.
func scoredState(t *testing.T) *AppsecRequestState {
	t.Helper()

	w := makeRuntime()
	state := &AppsecRequestState{HookVars: map[string]string{}}
	require.NoError(t, w.AddRequestScore(state, 100, "cdp", "fingerprint"))
	require.NoError(t, w.AddRequestScore(state, 15, "utc_timezone"))

	return state
}

// The two alert-context entry points read hook_vars from different places
// (see StampHookVars), so an operator writes different expressions for each.
// Both are pinned here: this is the contract a context.yaml is written
// against, and it is not otherwise covered by a test.
func TestRequestScoreInAlertContext(t *testing.T) {
	t.Run("challenge alerts, via evt", func(t *testing.T) {
		loadContextYAML(t, `
request_score:
  - evt.Appsec.HookVars.request_score
request_score_reasons:
  - evt.Appsec.HookVars.request_score_reasons
request_score_categories:
  - evt.Appsec.HookVars.request_score_categories
`)

		evt := pipeline.MakeEvent(false, pipeline.LOG, false)
		StampHookVars(&evt, scoredState(t))

		metas, errs := alertcontext.EventToContext([]pipeline.Event{evt})
		require.Empty(t, errs)

		got := contextMap(metas)
		assert.Equal(t, `["115"]`, got["request_score"])
		assert.Equal(t, `["fingerprint:cdp=100,utc_timezone=15"]`, got["request_score_reasons"])
		assert.Equal(t, `["fingerprint=100,utc_timezone=15"]`, got["request_score_categories"])
	})

	t.Run("waf alerts, via match", func(t *testing.T) {
		loadContextYAML(t, `
request_score:
  - match.hook_vars.request_score
request_score_reasons:
  - match.hook_vars.request_score_reasons
request_score_categories:
  - match.hook_vars.request_score_categories
`)

		evt := pipeline.MakeEvent(false, pipeline.LOG, false)
		evt.Appsec.MatchedRules = append(evt.Appsec.MatchedRules, *pipeline.NewMatchedRule())
		StampHookVars(&evt, scoredState(t))

		metas, errs := alertcontext.AppsecEventToContext(evt.Appsec, &http.Request{})
		require.Empty(t, errs)

		got := contextMap(metas)
		assert.Equal(t, `["115"]`, got["request_score"])
		assert.Equal(t, `["fingerprint:cdp=100,utc_timezone=15"]`, got["request_score_reasons"])
		assert.Equal(t, `["fingerprint=100,utc_timezone=15"]`, got["request_score_categories"])
	})
}
