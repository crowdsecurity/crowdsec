package appsec_rule

import (
	"errors"
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

type Match struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
	Not   bool   `yaml:"not,omitempty"`
}

type CustomRule struct {
	Name      string   `yaml:"name"`
	Severity  string   `yaml:"severity"`
	Zones     []string `yaml:"zones"`
	Variables []string `yaml:"variables"`

	Match     Match        `yaml:"match"`
	Transform []string     `yaml:"transform"` //t:lowercase, t:uppercase, etc
	And       []CustomRule `yaml:"and,omitempty"`
	Or        []CustomRule `yaml:"or,omitempty"`

	BodyType string `yaml:"body_type,omitempty"`
}

var (
	ErrMissingZones      = errors.New("no zones defined")
	ErrMissingMatchType  = errors.New("no match type defined")
	ErrMissingMatchValue = errors.New("no match value defined")
)

func (v *CustomRule) Convert(ruleType string, appsecRuleName string, appsecRuleDescription string) (string, []uint32, error) {
	if len(v.Zones) == 0 && len(v.And) == 0 && len(v.Or) == 0 {
		return "", nil, ErrMissingZones
	}

	if v.Match.Type == "" && len(v.And) == 0 && len(v.Or) == 0 {
		return "", nil, ErrMissingMatchType
	}

	if v.Match.Value == "" && len(v.And) == 0 && len(v.Or) == 0 {
		return "", nil, ErrMissingMatchValue
	}

	switch ruleType {
	case ModsecurityRuleType:
		r := ModsecurityRule{}
		return r.Build(v, appsecRuleName, appsecRuleDescription)
	default:
		return "", nil, fmt.Errorf("unknown rule format '%s'", ruleType)
	}
}
