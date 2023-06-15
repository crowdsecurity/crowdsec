package waf

import "strings"

type WafRule struct {
	RawRule string
}

// This is the "compiled" state of a WafConfig
type WafRulesCollection struct {
	Rules           []WafRule
	CompiledOnLoad  []CompiledHook `yaml:"-"`
	CompiledPreEval []CompiledHook `yaml:"-"`
	CompiledOnMatch []CompiledHook `yaml:"-"`
	OutOfBand       bool
}

func (w *WafRulesCollection) SetInBand() error {
	w.OutOfBand = false
	return nil
}

func (w *WafRulesCollection) SetOutOfBand() error {
	w.OutOfBand = true
	return nil
}

func (w *WafRulesCollection) String() string {
	//return strings.Join(w.Rules, "\n")
	var rules []string
	for _, rule := range w.Rules {
		rules = append(rules, rule.RawRule)
	}
	return strings.Join(rules, "\n")
}
