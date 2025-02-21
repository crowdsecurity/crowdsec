package appsec_rule

import "testing"

func TestVPatchRuleString(t *testing.T) {
	tests := []struct {
		name     string
		rule     CustomRule
		expected string
	}{
		{
			name: "Collection count",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "eq", Value: "1"},
				Transform: []string{"count"},
			},
			expected: `SecRule &ARGS_GET:foo "@eq 1" "id:853070236,phase:2,deny,log,msg:'Collection count',tag:'crowdsec-Collection count'"`,
		},
		{
			name: "Base Rule",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2203944045,phase:2,deny,log,msg:'Base Rule',tag:'crowdsec-Base Rule',t:lowercase"`,
		},
		{
			name: "One zone, multi var",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar "@rx [^a-zA-Z]" "id:385719930,phase:2,deny,log,msg:'One zone, multi var',tag:'crowdsec-One zone, multi var',t:lowercase"`,
		},
		{
			name: "Base Rule #2",
			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto"},
			},
			expected: `SecRule REQUEST_METHOD "@beginsWith toto" "id:2759779019,phase:2,deny,log,msg:'Base Rule #2',tag:'crowdsec-Base Rule #2'"`,
		},
		{
			name: "Base Negative Rule",
			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto", Not: true},
			},
			expected: `SecRule REQUEST_METHOD "!@beginsWith toto" "id:3966251995,phase:2,deny,log,msg:'Base Negative Rule',tag:'crowdsec-Base Negative Rule'"`,
		},
		{
			name: "Multiple Zones",
			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_POST:foo "@rx [^a-zA-Z]" "id:3387135861,phase:2,deny,log,msg:'Multiple Zones',tag:'crowdsec-Multiple Zones',t:lowercase"`,
		},
		{
			name: "Multiple Zones Multi Var",
			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar|ARGS_POST:foo|ARGS_POST:bar "@rx [^a-zA-Z]" "id:1119773585,phase:2,deny,log,msg:'Multiple Zones Multi Var',tag:'crowdsec-Multiple Zones Multi Var',t:lowercase"`,
		},
		{
			name: "Multiple Zones No Vars",
			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET|ARGS_POST "@rx [^a-zA-Z]" "id:2020110336,phase:2,deny,log,msg:'Multiple Zones No Vars',tag:'crowdsec-Multiple Zones No Vars',t:lowercase"`,
		},
		{
			name: "Basic AND",
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:4145519614,phase:2,deny,log,msg:'Basic AND',tag:'crowdsec-Basic AND',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1865217529,phase:2,deny,log,msg:'Basic AND',tag:'crowdsec-Basic AND',t:lowercase"`,
		},
		{
			name: "Basic OR",
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:651140804,phase:2,deny,log,msg:'Basic OR',tag:'crowdsec-Basic OR',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:271441587,phase:2,deny,log,msg:'Basic OR',tag:'crowdsec-Basic OR',t:lowercase"`,
		},
		{
			name: "OR AND mix",
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1714963250,phase:2,deny,log,msg:'OR AND mix',tag:'crowdsec-OR AND mix',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1519945803,phase:2,deny,log,msg:'OR AND mix',tag:'crowdsec-OR AND mix',t:lowercase"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1519945803,phase:2,deny,log,msg:'OR AND mix',tag:'crowdsec-OR AND mix',t:lowercase"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name)
			if err != nil {
				t.Errorf("Error converting rule: %s", err)
			}
			if actual != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, actual)
			}
		})
	}
}
