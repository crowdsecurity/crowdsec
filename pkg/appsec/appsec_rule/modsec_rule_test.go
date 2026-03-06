package appsec_rule

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type ruleTest struct {
	name        string
	rule        CustomRule
	expected    string
	expectedErr error
}

func runRuleTests(t *testing.T, tests []ruleTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name, "test rule")
			require.ErrorIs(t, err, tt.expectedErr)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestConvert(t *testing.T) {
	tests := []ruleTest{
		{
			name: "Missing zone (nil)",
			rule: CustomRule{
				Zones: nil,
			},
			expectedErr: ErrMissingZones,
		},
		{
			name: "Missing zone (empty slice)",
			rule: CustomRule{
				Zones: []string{},
			},
			expectedErr: ErrMissingZones,
		},
		{
			name: "Missing match type",
			rule: CustomRule{
				Zones: []string{"ARGS"},
				Match: Match{Type: "", Value: "value"},
			},
			expectedErr: ErrMissingMatchType,
		},
		{
			name: "Missing match value",
			rule: CustomRule{
				Zones: []string{"ARGS"},
				Match: Match{
					Type:  "type",
					Value: "",
				},
			},
			expectedErr: ErrMissingMatchValue,
		},
	}

	runRuleTests(t, tests)
}

func TestVPatchRuleString(t *testing.T) {
	tests := []ruleTest{
		{
			name: "Collection count",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "eq", Value: "1"},
				Transform: []string{"count"},
			},
			expected: `SecRule &ARGS_GET:foo "@eq 1" "id:853070236,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Collection count',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Base Rule",

			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2203944045,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Rule',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name: "One zone, multi var",

			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar "@rx [^a-zA-Z]" "id:385719930,phase:1,deny,log,msg:'test rule',tag:'crowdsec-One zone, multi var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name: "Base Rule #2",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto"},
			},
			expected: `SecRule REQUEST_METHOD "@beginsWith toto" "id:2759779019,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Rule #2',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Base Negative Rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto", Not: true},
			},
			expected: `SecRule REQUEST_METHOD "!@beginsWith toto" "id:3966251995,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Base Negative Rule',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Multiple Zones",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_POST:foo "@rx [^a-zA-Z]" "id:3387135861,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name: "Multiple Zones Multi Var",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Variables: []string{"foo", "bar"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar|ARGS_POST:foo|ARGS_POST:bar "@rx [^a-zA-Z]" "id:1119773585,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones Multi Var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name: "Multiple Zones No Vars",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET|ARGS_POST "@rx [^a-zA-Z]" "id:2020110336,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones No Vars',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:4145519614,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1865217529,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:651140804,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:271441587,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1714963250,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1519945803,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1519945803,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
	}

	runRuleTests(t, tests)
}

func TestPhaseOptimization(t *testing.T) {
	tests := []ruleTest{
		{
			name: "Phase 1 Rule - Headers",
			rule: CustomRule{
				Zones:     []string{"HEADERS"},
				Variables: []string{"User-Agent"},
				Match:     Match{Type: "contains", Value: "bot"},
			},
			expected: `SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:906121382,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - Headers',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Phase 1 Rule - Method",
			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "equals", Value: "POST"},
			},
			expected: `SecRule REQUEST_METHOD "@streq POST" "id:704636723,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - Method',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Phase 1 Rule - URI",
			rule: CustomRule{
				Zones: []string{"URI"},
				Match: Match{Type: "startsWith", Value: "/admin"},
			},
			expected: `SecRule REQUEST_FILENAME "@beginsWith /admin" "id:1629291161,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - URI',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Phase 1 Rule - GET Args",
			rule: CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{"id"},
				Match:     Match{Type: "regex", Value: "[0-9]+"},
			},
			expected: `SecRule ARGS_GET:id "@rx [0-9]+" "id:2620103902,phase:1,deny,log,msg:'test rule',tag:'crowdsec-Phase 1 Rule - GET Args',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Phase 2 Rule - Body Args",
			rule: CustomRule{
				Zones:     []string{"BODY_ARGS"},
				Variables: []string{"password"},
				Match:     Match{Type: "regex", Value: ".{8,}"},
				Transform: []string{"length"},
			},
			expected: `SecRule ARGS_POST:password "@rx .{8,}" "id:3965595689,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Body Args',tag:'cs-custom-rule',severity:'emergency',t:length"`,
		},
		{
			name: "Phase 2 Rule - Files",
			rule: CustomRule{
				Zones:     []string{"FILES"},
				Match:     Match{Type: "gt", Value: "0"},
				Transform: []string{"count"},
			},
			expected: `SecRule FILES "@gt 0" "id:3952889566,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Files',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Phase 2 Rule - Body Type",
			rule: CustomRule{
				Zones:     []string{"HEADERS"},
				Variables: []string{"Content-Type"},
				Match:     Match{Type: "contains", Value: "json"},
				BodyType:  "json",
			},
			expected: `SecRule REQUEST_HEADERS:Content-Type "@contains json" "id:2497270550,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Phase 2 Rule - Body Type',tag:'cs-custom-rule',severity:'emergency',ctl:requestBodyProcessor=JSON"`,
		},
		{
			name: "Mixed Zones - Phase 2 Required",
			rule: CustomRule{
				Zones:     []string{"HEADERS", "BODY_ARGS"},
				Variables: []string{"Content-Type"},
				Match:     Match{Type: "regex", Value: "malicious"},
			},
			expected: `SecRule REQUEST_HEADERS:Content-Type|ARGS_POST:Content-Type "@rx malicious" "id:2749918501,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Mixed Zones - Phase 2 Required',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name: "Chained Rules - Phase 1 Compatible",
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
			name: "Chained Rules - Phase 2 Required",
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
			name: "OR Rules - All Use Max Phase",
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
			// Both rules must be phase 2 because OR uses skip, which requires same phase
			expected: `SecRule ARGS_POST:username "@streq admin" "id:1971397178,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - All Use Max Phase',tag:'cs-custom-rule',severity:'emergency',skip:1"
SecRule REQUEST_HEADERS:Authorization "@beginsWith Bearer" "id:3649305393,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - All Use Max Phase',tag:'cs-custom-rule'"`,
		},
		{
			name: "AND Rules - Phase 2 First, Phase 1 Second (Both Forced to Phase 2)",
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
		{
			name: "OR Rules - All Phase 1",
			rule: CustomRule{
				Or: []CustomRule{
					{
						Zones:     []string{"HEADERS"},
						Variables: []string{"User-Agent"},
						Match:     Match{Type: "contains", Value: "bot"},
					},
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "POST"},
					},
				},
			},
			// All phase 1, so all rules stay phase 1
			expected: `SecRule REQUEST_HEADERS:User-Agent "@contains bot" "id:2414335292,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - All Phase 1',tag:'cs-custom-rule',severity:'emergency',skip:1"
SecRule REQUEST_METHOD "@streq POST" "id:4100634459,phase:1,deny,log,msg:'test rule',tag:'crowdsec-OR Rules - All Phase 1',tag:'cs-custom-rule'"`,
		},
		{
			name: "Nested AND Chain - Inner Phase 2 Forces Outer",
			rule: CustomRule{
				And: []CustomRule{
					{
						Zones: []string{"HEADERS"},
						Match: Match{Type: "contains", Value: "bot"},
					},
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "POST"},
						And: []CustomRule{
							{
								Zones:     []string{"BODY_ARGS"},
								Variables: []string{"action"},
								Match:     Match{Type: "equals", Value: "delete"},
							},
						},
					},
				},
			},
			// Nested AND has BODY_ARGS (phase 2), so entire chain is phase 2
			expected: `SecRule REQUEST_HEADERS "@contains bot" "id:2470939732,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested AND Chain - Inner Phase 2 Forces Outer',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule ARGS_POST:action "@streq delete" "id:1632333098,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested AND Chain - Inner Phase 2 Forces Outer',tag:'cs-custom-rule',severity:'emergency'"
SecRule REQUEST_METHOD "@streq POST" "id:1650126244,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested AND Chain - Inner Phase 2 Forces Outer',tag:'cs-custom-rule'"`,
		},
		{
			name: "Nested OR - Inner Phase 2 Forces All",
			rule: CustomRule{
				Or: []CustomRule{
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "GET"},
					},
					{
						Zones: []string{"HEADERS"},
						Match: Match{Type: "contains", Value: "bot"},
						Or: []CustomRule{
							{
								Zones:     []string{"BODY_ARGS"},
								Variables: []string{"id"},
								Match:     Match{Type: "regex", Value: "[0-9]+"},
							},
						},
					},
				},
			},
			// Nested OR has BODY_ARGS (phase 2), so all OR rules use phase 2
			expected: `SecRule REQUEST_METHOD "@streq GET" "id:1188325159,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested OR - Inner Phase 2 Forces All',tag:'cs-custom-rule',severity:'emergency',skip:1"
SecRule ARGS_POST:id "@rx [0-9]+" "id:3600614865,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested OR - Inner Phase 2 Forces All',tag:'cs-custom-rule',severity:'emergency'"
SecRule REQUEST_HEADERS "@contains bot" "id:3038570991,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Nested OR - Inner Phase 2 Forces All',tag:'cs-custom-rule'"`,
		},
	}

	runRuleTests(t, tests)
}
