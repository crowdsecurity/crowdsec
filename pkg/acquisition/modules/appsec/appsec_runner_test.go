package appsecacquisition

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/appsec_rule"
)

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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loadAppSecEngine(test, t)
		})
	}
}
