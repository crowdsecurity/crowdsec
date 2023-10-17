package waf

import "testing"

func TestVPatchRuleString(t *testing.T) {
	tests := []struct {
		name     string
		rule     VPatchRule
		expected string
	}{
		{
			name: "Base Rule",
			rule: VPatchRule{
				Target:    "ARGS",
				Variable:  "foo",
				Match:     "[^a-zA-Z]",
				Transform: "lowercase",
			},
			expected: `SecRule ARGS:foo "@rx [^a-zA-Z]" "id:0,deny,log,t:lowercase"`,
		},
		{
			name: "AND Logic Rule",
			rule: VPatchRule{
				Target:   "ARGS",
				Variable: "bar",
				Match:    "[0-9]",
				Logic:    "AND",
				SubRules: []VPatchRule{
					{
						Target: "REQUEST_URI",
						Match:  "/joomla/index.php/component/users/",
					},
				},
			},
			expected: `SecRule ARGS:bar "@rx [0-9]" "id:0,deny,log,chain"
SecRule REQUEST_URI "@rx /joomla/index.php/component/users/" "id:0,deny,log"`,
		},
		{
			name: "OR Logic Rule",
			rule: VPatchRule{
				Target:   "REQUEST_HEADERS",
				Variable: "User-Agent",
				Match:    "BadBot",
				Logic:    "OR",
				SubRules: []VPatchRule{
					{
						Target:   "REQUEST_HEADERS",
						Variable: "Referer",
						Match:    "EvilReferer",
					},
					{
						Target: "REQUEST_METHOD",
						Equals: "POST",
					},
				},
			},
			expected: `SecRule REQUEST_HEADERS:User-Agent "@rx BadBot" "id:0,deny,log,skip:2"
SecRule REQUEST_HEADERS:Referer "@rx EvilReferer" "id:0,deny,log,skip:1"
SecRule REQUEST_METHOD "@eq POST" "id:0,deny,log"`,
		},
		{
			name: "AND-OR Logic Mix",
			rule: VPatchRule{
				Target: "REQUEST_URI",
				Match:  "/api/",
				Logic:  "AND",
				SubRules: []VPatchRule{
					{
						Target:   "ARGS",
						Variable: "username",
						Match:    "admin",
						Logic:    "OR",
						SubRules: []VPatchRule{
							{
								Target: "REQUEST_METHOD",
								Equals: "POST",
								Logic:  "AND",
								SubRules: []VPatchRule{
									{
										Target:   "ARGS",
										Variable: "action",
										Match:    "delete",
									},
								},
							},
						},
					},
				},
			},
			expected: `SecRule REQUEST_URI "@rx /api/" "id:0,deny,log,chain"
SecRule ARGS:username "@rx admin" "id:0,deny,log,skip:2"
SecRule REQUEST_METHOD "@eq POST" "id:0,deny,log,chain"
SecRule ARGS:action "@rx delete" "id:0,deny,log"`,
		},
		// Additional OR test case would be here, but note that the OR logic representation with `skip` is very simplistic.
		// It may not be robust enough for complex OR rules in a real-world ModSecurity setup.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.rule.String()
			if actual != tt.expected {
				t.Errorf("Expected:\n%s\nGot:\n%s", tt.expected, actual)
			}
		})
	}
}
