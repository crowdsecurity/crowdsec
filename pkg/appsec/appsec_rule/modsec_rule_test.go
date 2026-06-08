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
			expected: `SecRule &ARGS_GET:foo "@eq 1" "id:784839152,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Collection count',tag:'cs-custom-rule',severity:'emergency'"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:426728273,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Rule',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar "@rx [^a-zA-Z]" "id:3295043918,phase:2,deny,log,msg:'test rule',tag:'crowdsec-One zone, multi var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Base Rule #2",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto"},
			},
			expected: `SecRule REQUEST_METHOD "@beginsWith toto" "id:106084967,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Rule #2',tag:'cs-custom-rule',severity:'emergency'"`,
		},
		{
			name:        "Base Negative Rule",
			description: "test rule",

			rule: CustomRule{
				Zones: []string{"METHOD"},
				Match: Match{Type: "startsWith", Value: "toto", Not: true},
			},
			expected: `SecRule REQUEST_METHOD "!@beginsWith toto" "id:1561051063,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Base Negative Rule',tag:'cs-custom-rule',severity:'emergency'"`,
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
			expected: `SecRule ARGS_GET:foo|ARGS_POST:foo "@rx [^a-zA-Z]" "id:1176299393,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo|ARGS_GET:bar|ARGS_POST:foo|ARGS_POST:bar "@rx [^a-zA-Z]" "id:2142736261,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones Multi Var',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
		},
		{
			name:        "Multiple Zones No Vars",
			description: "test rule",

			rule: CustomRule{
				Zones:     []string{"ARGS", "BODY_ARGS"},
				Match:     Match{Type: "regex", Value: "[^a-zA-Z]"},
				Transform: []string{"lowercase"},
			},
			expected: `SecRule ARGS_GET|ARGS_POST "@rx [^a-zA-Z]" "id:3150922420,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Multiple Zones No Vars',tag:'cs-custom-rule',severity:'emergency',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:3951337643,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:1797871498,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic AND',tag:'cs-custom-rule',t:lowercase"`,
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:2861427001,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',severity:'emergency',t:lowercase,skip:1"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:2619082328,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Basic OR',tag:'cs-custom-rule',t:lowercase"`,
		},
		{
			// leaf(foo) AND (foo OR bar) → DNF: (foo AND foo) OR (foo AND bar) → 2 groups of 2
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
			expected: `SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:1202606032,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:359710097,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase,skip:2"
SecRule ARGS_GET:foo "@rx [^a-zA-Z]" "id:3120021894,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase,chain"
SecRule ARGS_GET:bar "@rx [^a-zA-Z]" "id:2229098023,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR AND mix',tag:'cs-custom-rule',t:lowercase"`,
		},
		{
			// (A OR B) AND C → DNF: (A AND C) OR (B AND C)
			name:        "OR inside AND",
			description: "test rule",

			rule: CustomRule{
				And: []CustomRule{
					{
						Or: []CustomRule{
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"a"},
								Match:     Match{Type: "regex", Value: "x"},
								Transform: []string{"lowercase"},
							},
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"b"},
								Match:     Match{Type: "regex", Value: "x"},
								Transform: []string{"lowercase"},
							},
						},
					},
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "GET"},
					},
				},
			},
			expected: `SecRule ARGS_GET:a "@rx x" "id:1800648982,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR inside AND',tag:'cs-custom-rule',severity:'emergency',t:lowercase,chain"
SecRule REQUEST_METHOD "@streq GET" "id:1587988738,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR inside AND',tag:'cs-custom-rule',skip:2"
SecRule ARGS_GET:b "@rx x" "id:3192999968,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR inside AND',tag:'cs-custom-rule',t:lowercase,chain"
SecRule REQUEST_METHOD "@streq GET" "id:3752698388,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR inside AND',tag:'cs-custom-rule'"`,
		},
		{
			// (A OR B) AND (C OR D) → DNF: (A,C) OR (A,D) OR (B,C) OR (B,D)
			name:        "OR cross product",
			description: "test rule",

			rule: CustomRule{
				And: []CustomRule{
					{
						Or: []CustomRule{
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"a"},
								Match:     Match{Type: "regex", Value: "x"},
							},
							{
								Zones:     []string{"ARGS"},
								Variables: []string{"b"},
								Match:     Match{Type: "regex", Value: "x"},
							},
						},
					},
					{
						Or: []CustomRule{
							{
								Zones:     []string{"HEADERS"},
								Variables: []string{"c"},
								Match:     Match{Type: "contains", Value: "y"},
							},
							{
								Zones:     []string{"HEADERS"},
								Variables: []string{"d"},
								Match:     Match{Type: "contains", Value: "y"},
							},
						},
					},
				},
			},
			expected: `SecRule ARGS_GET:a "@rx x" "id:4076736575,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule REQUEST_HEADERS:c "@contains y" "id:3029228238,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',skip:6"
SecRule ARGS_GET:a "@rx x" "id:3671513773,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',chain"
SecRule REQUEST_HEADERS:d "@contains y" "id:2068477400,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',skip:4"
SecRule ARGS_GET:b "@rx x" "id:2234139251,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',chain"
SecRule REQUEST_HEADERS:c "@contains y" "id:1870138418,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',skip:2"
SecRule ARGS_GET:b "@rx x" "id:1039790593,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule',chain"
SecRule REQUEST_HEADERS:d "@contains y" "id:3758321836,phase:2,deny,log,msg:'test rule',tag:'crowdsec-OR cross product',tag:'cs-custom-rule'"`,
		},
		{
			// Same level and+or: POST AND (a OR b)
			name:        "Same level AND OR",
			description: "test rule",

			rule: CustomRule{
				And: []CustomRule{
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "POST"},
					},
				},
				Or: []CustomRule{
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"a"},
						Match:     Match{Type: "regex", Value: "x"},
					},
					{
						Zones:     []string{"ARGS"},
						Variables: []string{"b"},
						Match:     Match{Type: "regex", Value: "x"},
					},
				},
			},
			expected: `SecRule REQUEST_METHOD "@streq POST" "id:3395404975,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Same level AND OR',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule ARGS_GET:a "@rx x" "id:3880988910,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Same level AND OR',tag:'cs-custom-rule',skip:2"
SecRule REQUEST_METHOD "@streq POST" "id:3808442053,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Same level AND OR',tag:'cs-custom-rule',chain"
SecRule ARGS_GET:b "@rx x" "id:1637823048,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Same level AND OR',tag:'cs-custom-rule'"`,
		},
		{
			// A AND (B OR (C AND D)) → DNF: (A,B) OR (A,C,D)
			name:        "Deep nesting",
			description: "test rule",

			rule: CustomRule{
				And: []CustomRule{
					{
						Zones: []string{"METHOD"},
						Match: Match{Type: "equals", Value: "POST"},
					},
					{
						Or: []CustomRule{
							{
								Zones:     []string{"URI"},
								Match:     Match{Type: "contains", Value: "/admin"},
								Transform: []string{"lowercase"},
							},
							{
								And: []CustomRule{
									{
										Zones:     []string{"ARGS"},
										Variables: []string{"cmd"},
										Match:     Match{Type: "regex", Value: "exec"},
									},
									{
										Zones:     []string{"HEADERS"},
										Variables: []string{"x-debug"},
										Match:     Match{Type: "equals", Value: "true"},
									},
								},
							},
						},
					},
				},
			},
			expected: `SecRule REQUEST_METHOD "@streq POST" "id:4151628139,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Deep nesting',tag:'cs-custom-rule',severity:'emergency',chain"
SecRule REQUEST_FILENAME "@contains /admin" "id:2534092724,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Deep nesting',tag:'cs-custom-rule',t:lowercase,skip:3"
SecRule REQUEST_METHOD "@streq POST" "id:220760465,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Deep nesting',tag:'cs-custom-rule',chain"
SecRule ARGS_GET:cmd "@rx exec" "id:2515501355,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Deep nesting',tag:'cs-custom-rule',chain"
SecRule REQUEST_HEADERS:x-debug "@streq true" "id:1447329030,phase:2,deny,log,msg:'test rule',tag:'crowdsec-Deep nesting',tag:'cs-custom-rule'"`,
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
			actual, _, err := tt.rule.Convert(ModsecurityRuleType, tt.name, tt.description, 0)
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

func TestDNFExpansionLimit(t *testing.T) {
	// Create a rule that would produce too many DNF groups
	// 3 OR-groups with 5 items each → 5*5*5 = 125 groups > 50 limit
	makeOrGroup := func() CustomRule {
		items := make([]CustomRule, 5)
		for i := range items {
			items[i] = CustomRule{
				Zones:     []string{"ARGS"},
				Variables: []string{string(rune('a' + i))},
				Match:     Match{Type: "regex", Value: "x"},
			}
		}
		return CustomRule{Or: items}
	}

	rule := CustomRule{
		And: []CustomRule{
			makeOrGroup(),
			makeOrGroup(),
			makeOrGroup(),
		},
	}

	_, _, err := rule.Convert(ModsecurityRuleType, "test", "test", 0)
	if err == nil {
		t.Error("Expected error for excessive DNF expansion, got nil")
	}
}

// TestRuleIDUniqueAcrossRulesInCollection: an identical leaf shared by two
// rules of the same collection must not collide on the same id (positions
// restart at 0 per rule). Regression test for crowdsecurity/vpatch-CVE-2024-34102.
func TestRuleIDUniqueAcrossRulesInCollection(t *testing.T) {
	const collection = "crowdsecurity/test"

	// identical zone/match/transform in both rules
	sharedLeaf := CustomRule{
		Zones:     []string{"URI"},
		Transform: []string{"lowercase"},
		Match:     Match{Type: "contains", Value: "/admin"},
	}

	rule0 := CustomRule{And: []CustomRule{
		{Zones: []string{"METHOD"}, Match: Match{Type: "equals", Value: "POST"}},
		sharedLeaf,
	}}
	rule1 := CustomRule{And: []CustomRule{
		{Zones: []string{"METHOD"}, Match: Match{Type: "equals", Value: "GET"}},
		sharedLeaf,
	}}

	_, ids0, err := rule0.Convert(ModsecurityRuleType, collection, "", 0)
	require.NoError(t, err)

	_, ids1, err := rule1.Convert(ModsecurityRuleType, collection, "", 1)
	require.NoError(t, err)

	seen := make(map[uint32]bool, len(ids0))
	for _, id := range ids0 {
		seen[id] = true
	}

	for _, id := range ids1 {
		require.Falsef(t, seen[id], "id %d generated by two different rules of the same collection", id)
	}
}
