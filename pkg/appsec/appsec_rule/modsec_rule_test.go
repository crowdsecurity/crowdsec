package appsec_rule

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

func TestVPatchRuleString(t *testing.T) {
	tests := []struct {
		name        string
		description string
		rule        CustomRule
		expected    string
		invalid     bool
	}{
		{
			name:        "Collection count",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "eq", Value: "1"},
				Transform: []string{"count"},
			},
			expected: `SecRule &ARGS_GET:foo "@eq 1" "id:853070236,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Collection count',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Base Rule",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2203944045,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Rule',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "One zone, multi var",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar "@rx [^a-zA-Z]" "id:385719930,phase:2,deny,log,msg:'test rule',tag:'crowdsec-One zone, multi var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Base Rule #2",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto"},
			},
			expected: `SecRule REQUEST_METHOD "@beginsWith toto" "id:2759779019,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Rule #2',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Base Negative Rule",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto", Not: true},
			},
			expected: `SecRule REQUEST_METHOD "!@beginsWith toto" "id:3966251995,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Negative Rule',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Multiple Zones",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_POST:foo "@rx [^a-zA-Z]" "id:3387135861,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Multiple Zones Multi Var",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar|ARGS_POST:foo|ARGS_POST:bar "@rx [^a-zA-Z]" "id:1119773585,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones Multi Var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Multiple Zones No Vars",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET|ARGS_POST "@rx [^a-zA-Z]" "id:2020110336,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones No Vars',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Basic AND",
			description: "test rule",

			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"bar"},
						Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:4145519614,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1865217529,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',t:lowercase"`,
		},
		{
			name:        "Basic OR",
			description: "test rule",

			rule: CustomRule{
				Or: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"bar"},
						Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:651140804,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:271441587,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',t:lowercase"`,
		},
		{
			name:        "OR AND mix",
			description: "test rule",
			invalid:     true,

			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
						Or: []CustomRule{
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"foo"},
								Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
								Transform: []string{"lowercase"},
							},
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"bar"},
								Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
								Transform: []string{"lowercase"},
							},
						},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1714963250,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1519945803,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1519945803,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name: "all transforms",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase", "uppercase", "length", "trim", "trim_left", "trim_right", "htmlentitydecode", "js_decode", "css_decode", "urldecode", "hexdecode", "cmdline", "b64decode", "b64decode_lenient", "b64encode", "normalize_path", "normalize_path_win", "remove_whitespaces", "compress_whitespaces", "remove_nulls", "replace_nulls", "remove_comments", "replace_comments"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name, tt.description)
			if err != nil {
				t.Errorf("Error converting rule: %s", err)
			}
			if tt.expected != "" && actual != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, actual)
			}
			// Attempt to parse the rule to make sure we generated a valid one
			cfg := coraza.NewWAFConfig().WithDirectives(actual)
			_, err = coraza.NewWAF(cfg)
			if tt.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
