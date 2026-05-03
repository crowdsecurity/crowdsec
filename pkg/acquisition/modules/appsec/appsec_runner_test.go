package appsecacquisition

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func TestCopyHookVars(t *testing.T) {
	t.Run("no hook vars is a no-op", func(t *testing.T) {
		evt := pipeline.Event{
			Appsec: pipeline.AppsecEvent{
				MatchedRules: pipeline.MatchedRules{{"id": 1}},
			},
		}
		state := &appsec.AppsecRequestState{HookVars: map[string]string{}}

		copyHookVars(&evt, state)

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
		state := &appsec.AppsecRequestState{
			HookVars: map[string]string{
				"validation_error":       "request_body: ...",
				"validation_error_field": "username",
			},
		}

		copyHookVars(&evt, state)

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
		state := &appsec.AppsecRequestState{
			HookVars: map[string]string{"k": "v1"},
		}

		copyHookVars(&evt, state)

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
		state := &appsec.AppsecRequestState{HookVars: map[string]string{"k": "v"}}

		copyHookVars(&evt, state)

		m0 := evt.Appsec.MatchedRules[0]["hook_vars"].(map[string]string)
		m1 := evt.Appsec.MatchedRules[1]["hook_vars"].(map[string]string)
		// Matches share the same snapshot map: mutating one is observable via the other.
		m0["extra"] = "y"
		require.Equal(t, "y", m1["extra"], "matches should share the same snapshot map")
	})
}

func TestAppsecConflictRuleLoad(t *testing.T) {
	log.SetLevel(log.TraceLevel)
	tests := []appsecRuleTest{
		{
			name:             "simple native rule load",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "id conflict on native rule load",
			expected_load_ok: false,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
			},
		},
		{
			name:             "simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "duplicate rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
	}

	runTests(t, tests)
}

func TestAppsecRuleLoad(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	tests := []appsecRuleTest{
		{
			name:             "simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "simple native rule load",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 1)
			},
		},
		{
			name:             "simple native rule load (2)",
			expected_load_ok: true,
			inband_native_rules: []string{
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^application/x-www-form-urlencoded" "id:100,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=URLENCODED"`,
				`Secrule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:101,phase:1,pass,nolog,noauditlog,ctl:requestBodyProcessor=MULTIPART"`,
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "multi simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "multi simple rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name:  "rule1",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
				{
					Name:  "rule2",
					Zones: []string{"ARGS"},
					Match: appsec_rule.Match{Type: "equals", Value: "toto"},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 2)
			},
		},
		{
			name:             "imbricated rule load",
			expected_load_ok: true,
			inband_rules: []appsec_rule.CustomRule{
				{
					Name: "rule1",

					Or: []appsec_rule.CustomRule{
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "toto"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "tutu"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "tata"},
						},
						{
							// Name:  "rule1",
							Zones: []string{"ARGS"},
							Match: appsec_rule.Match{Type: "equals", Value: "titi"},
						},
					},
				},
			},
			afterload_asserts: func(runner AppsecRunner) {
				require.Len(t, runner.AppsecInbandEngine.GetRuleGroup().GetRules(), 4)
			},
		},
		{
			name:             "invalid inband rule",
			expected_load_ok: false,
			inband_native_rules: []string{
				"this_is_not_a_rule",
			},
		},
		{
			name:             "invalid outofband rule",
			expected_load_ok: false,
			outofband_native_rules: []string{
				"this_is_not_a_rule",
			},
		},
	}

	runTests(t, tests)
}
