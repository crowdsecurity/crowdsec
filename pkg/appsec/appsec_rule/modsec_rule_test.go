package appsec_rule

import (
	"testing"
)

func TestVPatchRuleString(t *testing.T) {
	tests := []struct {
		name        string
		description string
		rule        CustomRule
		expected    string
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
			expected: `SecRule &ARGS_GET:foo "@eq 1" "id:853070236,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Collection count',tag:'cs-custom-rule',severity:'emergency'"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2203944045,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Rule',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar "@rx [^a-zA-Z]" "id:385719930,phase:1,deny,log,msg:'test rule',tag:'crowdsec-One zone, multi var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Base Rule #2",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto"},
			},
			expected: `SecRule REQUEST_METHOD "@beginsWith toto" "id:2759779019,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Rule #2',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Base Negative Rule",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto", Not: true},
			},
			expected: `SecRule REQUEST_METHOD "!@beginsWith toto" "id:3966251995,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Negative Rule',tag:'cs-custom-rule',severity:'emergency'"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:4145519614,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1865217529,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:651140804,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:271441587,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',t:lowercase"`,
		},
		{
			name:        "OR AND mix",
			description: "test rule",

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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1714963250,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1519945803,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1519945803,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name, tt.description)
			if err != nil {
				t.Errorf("Error converting rule: %s", err)
			}
			if actual != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, actual)
			}
		})
	}
}

func TestPhaseOptimization(t *testing.T) {
	tests := []struct {
		name        string
		description string
		rule        CustomRule
		expected    string
	}{
		{
			name:        "Phase 1 Rule - Headers",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"HEADERS"},
				Variables: []string{"User-Agent"},
				Match:     Match{Type: "contains", Value: "bot"},
			},
			expected: `SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:906121382,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - Headers',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Phase 1 Rule - Method",
			description: "test rule",
			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "equals", Value: "POST"},
			},
			expected: `SecRule REQUEST_METHOD "@streq POST" "id:704636723,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - Method',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Phase 1 Rule - URI",
			description: "test rule",
			rule: CustomRule{
				Zones: []string{"URI"},
				Match: Match{Type: "startsWith", Value: "/admin"},
			},
			expected: `SecRule REQUEST_FILENAME "@beginsWith /admin" "id:1629291161,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - URI',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Phase 1 Rule - GET Args",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"id"},
				Match:     Match{Type: "regex", Value: "[0-9]+"},
			},
			expected: `SecRule ARGS_GET:id "@rx [0-9]+" "id:2620103902,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - GET Args',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Phase 2 Rule - Body Args",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"BODY_ARGS"},
				Variables: []string{"password"},
				Match:     Match{Type: "regex", Value: ".{8,}"},
				Transform: []string{"length"},
			},
			expected: `SecRule ARGS_POST:password "@rx .{8,}" "id:3965595689,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Body Args',tag:'cs-custom-rule',severity:'emergency',t:length"`,
		},
		{
			name:        "Phase 2 Rule - Files",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"FILES"},
				Match:     Match{Type: "gt", Value: "0"},
				Transform: []string{"count"},
			},
			expected: `SecRule FILES "@gt 0" "id:3952889566,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Files',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Phase 2 Rule - Body Type",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"HEADERS"},
				Variables: []string{"Content-Type"},
				Match:     Match{Type: "contains", Value: "json"},
				BodyType:  "json",
			},
			expected: `SecRule REQUEST_HEADERS:Content-Type "@contains json" "id:2497270550,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Body Type',tag:'cs-custom-rule',severity:'emergency',ctl:requestBodyProcessor=JSON"`,
		},
		{
			name:        "Mixed Zones - Phase 2 Required",
			description: "test rule",
			rule: CustomRule{
				Zones:     []string{"HEADERS", "BODY_ARGS"},
				Variables: []string{"Content-Type"},
				Match:     Match{Type: "regex", Value: "malicious"},
			},
			expected: `SecRule REQUEST_HEADERS:Content-Type|ARGS_POST:Content-Type "@rx malicious" "id:2749918501,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Mixed Zones - Phase 2 Required',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Chained Rules - Phase 1 Compatible",
			description: "test rule",
			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"HEADERS"},
						Variables: []string{"User-Agent"},
						Match:     Match{Type: "contains", Value: "bot"},
					},
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "GET"},
					},
				},
			},
			expected: `SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:3202822048,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Chained Rules - Phase 1 Compatible',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule REQUEST_METHOD "@streq GET" "id:1698112565,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Chained Rules - Phase 1 Compatible',tag:'cs-custom-rule'"`,
		},
		{
			name:        "Chained Rules - Phase 2 Required",
			description: "test rule",
			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"HEADERS"},
						Variables: []string{"User-Agent"},
						Match:     Match{Type: "contains", Value: "bot"},
					},
					{
						Zones:     []string{"BODY_ARGS"},
						Variables: []string{"action"},
						Match:     Match{Type: "equals", Value: "delete"},
					},
				},
			},
			expected: `SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:2303496748,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Chained Rules - Phase 2 Required',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule ARGS_POST:action "@streq delete" "id:1325966539,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Chained Rules - Phase 2 Required',tag:'cs-custom-rule'"`,
		},
		{
			name:        "OR Rules - Phase 2 First, Phase 1 Second",
			description: "test rule",
			rule: CustomRule{
				Or: []CustomRule{
					{
						Zones:     []string{"BODY_ARGS"},
						Variables: []string{"username"},
						Match:     Match{Type: "equals", Value: "admin"},
					},
					{
						Zones:     []string{"HEADERS"},
						Variables: []string{"Authorization"},
						Match:     Match{Type: "startsWith", Value: "Bearer"},
					},
				},
			},
			expected: `SecRule ARGS_POST:username "@streq admin" "id:801106468,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - Phase 2 First, Phase 1 Second',tag:'cs-custom-rule',severity:'emergency',skip:1"
SecRule REQUEST_HEADERS:Authorization "@beginsWith Bearer" "id:3776099319,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - Phase 2 First, Phase 1 Second',tag:'cs-custom-rule'"`,
		},
		{
			name:        "AND Rules - Phase 2 First, Phase 1 Second (Both Forced to Phase 2)",
			description: "test rule",
			rule: CustomRule{
				And: []CustomRule{
					{
						Zones:     []string{"BODY_ARGS"},
						Variables: []string{"username"},
						Match:     Match{Type: "equals", Value: "admin"},
					},
					{
						Zones:     []string{"HEADERS"},
						Variables: []string{"Authorization"},
						Match:     Match{Type: "startsWith", Value: "Bearer"},
					},
				},
			},
			expected: `SecRule ARGS_POST:username "@streq admin" "id:3508654757,phase:2,deny,log,msg:'test rule',tag:'crowdsec-AND Rules - Phase 2 First, Phase 1 Second (Both Forced to Phase 2)',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule REQUEST_HEADERS:Authorization "@beginsWith Bearer" "id:438006436,phase:2,deny,log,msg:'test rule',tag:'crowdsec-AND Rules - Phase 2 First, Phase 1 Second (Both Forced to Phase 2)',tag:'cs-custom-rule'"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name, tt.description)
			if err != nil {
				t.Errorf("Error converting rule: %s", err)
			}
			if actual != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, actual)
			}
		})
	}
}
