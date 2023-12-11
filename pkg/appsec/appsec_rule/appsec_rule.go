package appsec_rule

import (
	"fmt"
)

/*
rules:
 - name: "test"
   and:
   	- zones:
   		- BODY_ARGS
   	  variables:
		- foo
		- bar
   	  transform:
   		- lowercase|uppercase|b64decode|...
	  match:
	    type: regex
	   	value: "[^a-zA-Z]"
	- zones:
	   - ARGS
	  variables:
	   - bla

*/

type match struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

type CustomRule struct {
	Name string `yaml:"name"`

	Zones     []string `yaml:"zones"`
	Variables []string `yaml:"variables"`

	Match     match        `yaml:"match"`
	Transform []string     `yaml:"transform"` //t:lowercase, t:uppercase, etc
	And       []CustomRule `yaml:"and,omitempty"`
	Or        []CustomRule `yaml:"or,omitempty"`
	BodyType  string       `yaml:"body_type,omitempty"`
}

func (v *CustomRule) Convert(ruleType string, appsecRuleName string) (string, []uint32, error) {

	if v.Zones == nil && v.And == nil && v.Or == nil {
		return "", nil, fmt.Errorf("no zones defined")
	}

	if v.Match.Type == "" && v.And == nil && v.Or == nil {
		return "", nil, fmt.Errorf("no match type defined")
	}

	if v.Match.Value == "" && v.And == nil && v.Or == nil {
		return "", nil, fmt.Errorf("no match value defined")
	}

	switch ruleType {
	case ModsecurityRuleType:
		r := ModsecurityRule{}
		return r.Build(v, appsecRuleName)
	default:
		return "", nil, fmt.Errorf("unknown rule format '%s'", ruleType)
	}
}
