package waap_rule

import "testing"

func TestVPatchRuleString(t *testing.T) {
	tests := []struct {
		name     string
		rule     CustomRule
		expected string
	}{
		{
			name: "Base Rule",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1136235475,phase:2,deny,log,msg:'Base Rule',t:lowercase"`,
		},
		{
			name: "Multiple Zones",
			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo"},
				Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_POST:foo "@rx [^a-zA-Z]" "id:2088895799,phase:2,deny,log,msg:'Multiple Zones',t:lowercase"`,
		},
		{
			name: "Basic AND",
			rule: CustomRule{
				And: []CustomRule{
					{

						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"bar"},
						Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2323451654,phase:2,deny,log,msg:'Basic AND_and_0',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:2075918819,phase:2,deny,log,msg:'Basic AND_and_1',t:lowercase"`,
		},
		{
			name: "Basic OR",
			rule: CustomRule{
				Or: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"bar"},
						Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2720972114,phase:2,deny,log,msg:'Basic OR_or_0',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:2638639999,phase:2,deny,log,msg:'Basic OR_or_1',t:lowercase"`,
		},
		{
			name: "OR AND mix",
			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"foo"},
						Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
						Transform: []string{"lowercase"},
						Or: []CustomRule{
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"foo"},
								Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
								Transform: []string{"lowercase"},
							},
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"bar"},
								Match:     match{Type: "regex", Value: "[^a-zA-Z]"},
								Transform: []string{"lowercase"},
							},
						},
					},
				},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2720972114,phase:2,deny,log,msg:'Basic OR_or_0',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:2638639999,phase:2,deny,log,msg:'Basic OR_or_1',t:lowercase"`,
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
