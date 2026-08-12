package appsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestStampHookVars(t *testing.T) {
	t.Run("nil state is a no-op", func(t *testing.T) {
		evt := pipeline.Event{
			Appsec: pipeline.AppsecEvent{
				MatchedRules: pipeline.MatchedRules{{"id": 1}},
			},
		}

		StampHookVars(&evt, nil)

		require.Nil(t, evt.Appsec.HookVars)
		_, ok := evt.Appsec.MatchedRules[0]["hook_vars"]
		require.False(t, ok)
	})

	t.Run("no hook vars is a no-op", func(t *testing.T) {
		evt := pipeline.Event{
			Appsec: pipeline.AppsecEvent{
				MatchedRules: pipeline.MatchedRules{{"id": 1}},
			},
		}
		state := &AppsecRequestState{HookVars: map[string]string{}}

		StampHookVars(&evt, state)

		require.Nil(t, evt.Appsec.HookVars)
		_, ok := evt.Appsec.MatchedRules[0]["hook_vars"]
		require.False(t, ok, "matched rule should not gain a hook_vars key when state has none")
	})

	t.Run("snapshots into event and onto each match", func(t *testing.T) {
		evt := pipeline.Event{
			Appsec: pipeline.AppsecEvent{
				MatchedRules: pipeline.MatchedRules{
					{"id": 1, "name": "rule-a"},
					{"id": 2, "name": "rule-b"},
				},
			},
		}
		state := &AppsecRequestState{
			HookVars: map[string]string{
				"validation_error":       "request_body: ...",
				"validation_error_field": "username",
			},
		}

		StampHookVars(&evt, state)

		require.Equal(t, "request_body: ...", evt.Appsec.HookVars["validation_error"])
		require.Equal(t, "username", evt.Appsec.HookVars["validation_error_field"])

		for i, match := range evt.Appsec.MatchedRules {
			hv, ok := match["hook_vars"].(map[string]string)
			require.True(t, ok, "match %d missing hook_vars", i)
			require.Equal(t, "username", hv["validation_error_field"])
		}
	})

	t.Run("event snapshot is decoupled from subsequent state mutations", func(t *testing.T) {
		evt := pipeline.Event{}
		state := &AppsecRequestState{
			HookVars: map[string]string{"k": "v1"},
		}

		StampHookVars(&evt, state)

		// Simulate an out-of-band phase mutating the scratch space.
		state.HookVars["k"] = "v2"
		state.HookVars["new"] = "x"

		require.Equal(t, "v1", evt.Appsec.HookVars["k"])
		_, hasNew := evt.Appsec.HookVars["new"]
		require.False(t, hasNew, "event snapshot must not reflect post-snapshot state mutations")
	})

	t.Run("all matches share the same snapshot reference", func(t *testing.T) {
		evt := pipeline.Event{
			Appsec: pipeline.AppsecEvent{
				MatchedRules: pipeline.MatchedRules{
					{"id": 1},
					{"id": 2},
				},
			},
		}
		state := &AppsecRequestState{HookVars: map[string]string{"k": "v"}}

		StampHookVars(&evt, state)

		m0 := evt.Appsec.MatchedRules[0]["hook_vars"].(map[string]string)
		m1 := evt.Appsec.MatchedRules[1]["hook_vars"].(map[string]string)
		// Matches share the same snapshot map: mutating one is observable via the other.
		m0["extra"] = "y"
		require.Equal(t, "y", m1["extra"], "matches should share the same snapshot map")
	})
}

func testAlert(t *testing.T) *models.Alert {
	t.Helper()

	ip := "1.2.3.4"

	return &models.Alert{
		Source: &models.Source{Value: &ip, IP: ip, Scope: new("Ip")},
	}
}

func TestNewAppsecOverflow(t *testing.T) {
	alert := testAlert(t)

	evt := NewAppsecOverflow(alert, map[string]string{"request_score": "105"})

	assert.Equal(t, pipeline.APPSEC, evt.Type)
	assert.True(t, evt.Process)
	assert.Same(t, alert, evt.Overflow.Alert)
	require.Len(t, evt.Overflow.APIAlerts, 1)
	require.Contains(t, evt.Overflow.Sources, "1.2.3.4")
	assert.Equal(t, "1.2.3.4", evt.Overflow.Sources["1.2.3.4"].IP)
	assert.Equal(t, "105", evt.Appsec.HookVars["request_score"])
}

func TestNewAppsecOverflowCopiesHookVars(t *testing.T) {
	src := map[string]string{"k": "v1"}

	evt := NewAppsecOverflow(testAlert(t), src)

	// The log event it was built from keeps living in the pipeline, where the
	// parsers mutate it.
	src["k"] = "v2"
	assert.Equal(t, "v1", evt.Appsec.HookVars["k"])
}

func TestNewAppsecOverflowNoHookVars(t *testing.T) {
	evt := NewAppsecOverflow(testAlert(t), nil)
	assert.Nil(t, evt.Appsec.HookVars)
}

func TestEmitEventNilChannel(t *testing.T) {
	w := makeRuntime() // OutChan is nil
	require.NotPanics(t, func() {
		w.EmitEvent(pipeline.Event{})
	})
}

func TestEmitAlertAndEventOrdersAlertFirst(t *testing.T) {
	out := make(chan pipeline.Event, 4)
	w := makeRuntime()
	w.OutChan = out

	overflow := NewAppsecOverflow(testAlert(t), nil)
	logEvt := pipeline.Event{Type: pipeline.LOG}

	w.EmitAlertAndEvent(&overflow, &logEvt)

	require.Len(t, out, 2)
	assert.Equal(t, pipeline.APPSEC, (<-out).Type, "the alert must be handed off before the log event")
	assert.Equal(t, pipeline.LOG, (<-out).Type)
}

func TestEmitAlertAndEventSkipsNils(t *testing.T) {
	out := make(chan pipeline.Event, 4)
	w := makeRuntime()
	w.OutChan = out

	logEvt := pipeline.Event{Type: pipeline.LOG}
	w.EmitAlertAndEvent(nil, &logEvt)
	require.Len(t, out, 1)
	assert.Equal(t, pipeline.LOG, (<-out).Type)

	overflow := NewAppsecOverflow(testAlert(t), nil)
	w.EmitAlertAndEvent(&overflow, nil)
	require.Len(t, out, 1)
	assert.Equal(t, pipeline.APPSEC, (<-out).Type)

	w.EmitAlertAndEvent(nil, nil)
	assert.Empty(t, out)
}
