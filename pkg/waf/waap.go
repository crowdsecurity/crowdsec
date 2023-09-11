package waf

import (
	"fmt"
	"regexp"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	corazatypes "github.com/crowdsecurity/coraza/v3/types"
	log "github.com/sirupsen/logrus"
)

type Hook struct {
	Filter     string      `yaml:"filter"`
	FilterExpr *vm.Program `yaml:"-"`

	OnSuccess string        `yaml:"on_success"`
	Apply     []string      `yaml:"apply"`
	ApplyExpr []*vm.Program `yaml:"-"`
}

func (h *Hook) Build() error {

	if h.Filter != "" {
		program, err := expr.Compile(h.Filter) //FIXME: opts
		if err != nil {
			return fmt.Errorf("unable to compile filter %s : %w", h.Filter, err)
		}
		h.FilterExpr = program
	}
	for _, apply := range h.Apply {
		program, err := expr.Compile(apply, GetExprWAFOptions(GetEnv())...)
		if err != nil {
			return fmt.Errorf("unable to compile apply %s : %w", apply, err)
		}
		h.ApplyExpr = append(h.ApplyExpr, program)
	}
	return nil
}

// runtime version of WaapConfig
type WaapRuntimeConfig struct {
	Name                      string
	OutOfBandRules            []WaapCollection
	OutOfBandTx               ExtendedTransaction //is it a good idea ?
	InBandRules               []WaapCollection
	InBandTx                  ExtendedTransaction //is it a good idea ?
	DefaultRemediation        string
	CompiledOnLoad            []Hook
	CompiledPreEval           []Hook
	CompiledOnMatch           []Hook
	CompiledVariablesTracking []*regexp.Regexp
}

type WaapConfig struct {
	Name               string   `yaml:"name"`
	OutOfBandRules     []string `yaml:"outofband_rules"`
	InBandRules        []string `yaml:"inband_rules"`
	DefaultRemediation string   `yaml:"default_remediation"`
	OnLoad             []Hook   `yaml:"on_load"`
	PreEval            []Hook   `yaml:"pre_eval"`
	OnMatch            []Hook   `yaml:"on_match"`
	VariablesTracking  []string `yaml:"variables_tracking"`
}

func (wc *WaapConfig) Build() (*WaapRuntimeConfig, error) {
	ret := &WaapRuntimeConfig{}
	ret.Name = wc.Name
	ret.DefaultRemediation = wc.DefaultRemediation

	//load rules
	for _, rule := range wc.OutOfBandRules {
		collection, err := LoadCollection(rule)
		if err != nil {
			return nil, fmt.Errorf("unable to load outofband rule %s : %s", rule, err)
		}
		ret.OutOfBandRules = append(ret.OutOfBandRules, collection)
	}

	for _, rule := range wc.InBandRules {
		collection, err := LoadCollection(rule)
		if err != nil {
			return nil, fmt.Errorf("unable to load inband rule %s : %s", rule, err)
		}
		ret.InBandRules = append(ret.InBandRules, collection)
	}

	//load hooks
	for _, hook := range wc.OnLoad {
		err := hook.Build()
		if err != nil {
			return nil, fmt.Errorf("unable to build on_load hook : %s", err)
		}
		ret.CompiledOnLoad = append(ret.CompiledOnLoad, hook)
	}

	for _, hook := range wc.PreEval {
		err := hook.Build()
		if err != nil {
			return nil, fmt.Errorf("unable to build pre_eval hook : %s", err)
		}
		ret.CompiledPreEval = append(ret.CompiledPreEval, hook)
	}

	for _, hook := range wc.OnMatch {
		err := hook.Build()
		if err != nil {
			return nil, fmt.Errorf("unable to build on_match hook : %s", err)
		}
		ret.CompiledOnMatch = append(ret.CompiledOnMatch, hook)
	}

	//variable tracking
	for _, variable := range wc.VariablesTracking {
		compiledVariableRule, err := regexp.Compile(variable)
		if err != nil {
			return nil, fmt.Errorf("cannot compile variable regexp %s: %w", variable, err)
		}
		ret.CompiledVariablesTracking = append(ret.CompiledVariablesTracking, compiledVariableRule)
	}
	return ret, nil
}

func (w *WaapRuntimeConfig) ProcessOnMatchRules(request ParsedRequest, response ResponseRequest) error {

	for _, rule := range w.CompiledOnMatch {
		if rule.FilterExpr != nil {
			output, err := expr.Run(rule.FilterExpr, map[string]interface{}{
				//"rules": rules, //is it still useful ?
				"req": request,
			})
			if err != nil {
				return fmt.Errorf("unable to run filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Infof("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		for _, applyExpr := range rule.ApplyExpr {
			_, err := expr.Run(applyExpr, map[string]interface{}{
				//"rules":                 w.InBandTx.Tx.Rules, //what is it supposed to be ? matched rules ?
				"req":                   request,
				"RemoveInbandRuleByID":  w.RemoveInbandRuleByID,
				"RemoveOutbandRuleByID": w.RemoveOutbandRuleByID,
				"SetRemediation":        response.SetRemediation,
				"SetRemediationByID":    response.SetRemediationByID,
				"CancelEvent":           response.CancelEvent,
			})
			if err != nil {
				log.Errorf("unable to apply filter: %s", err)
				continue
			}
		}
	}
	return nil
}

func (w *WaapRuntimeConfig) ProcessPreEvalRules(request ParsedRequest) error {
	for _, rule := range w.CompiledPreEval {
		if rule.FilterExpr != nil {
			output, err := expr.Run(rule.FilterExpr, map[string]interface{}{
				//"rules": rules, //is it still useful ?
				"req": request,
			})
			if err != nil {
				return fmt.Errorf("unable to run filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Infof("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		// here means there is no filter or the filter matched
		for _, applyExpr := range rule.ApplyExpr {
			_, err := expr.Run(applyExpr, map[string]interface{}{
				"inband_rules":          w.InBandRules,
				"outband_rules":         w.OutOfBandRules,
				"req":                   request,
				"RemoveInbandRuleByID":  w.RemoveInbandRuleByID,
				"RemoveOutbandRuleByID": w.RemoveOutbandRuleByID,
			})
			if err != nil {
				log.Errorf("unable to apply filter: %s", err)
				continue
			}
		}
	}

	return nil
}

func (w *WaapRuntimeConfig) RemoveInbandRuleByID(id int) {
	w.InBandTx.RemoveRuleByIDWithError(id)
}

func (w *WaapRuntimeConfig) RemoveOutbandRuleByID(id int) {
	w.OutOfBandTx.RemoveRuleByIDWithError(id)
}

func (w *WaapRuntimeConfig) ProcessInBandRules(request ParsedRequest) (*corazatypes.Interruption, error) {
	for _, rule := range w.InBandRules {
		interrupt, err := rule.Eval(request)
		if err != nil {
			return nil, fmt.Errorf("unable to process inband rule %s : %s", rule.GetDisplayName(), err)
		}
		if interrupt != nil {
			return interrupt, nil
		}
	}
	return nil, nil
}

func (w *WaapRuntimeConfig) ProcessOutOfBandRules(request ParsedRequest) (*corazatypes.Interruption, error) {
	for _, rule := range w.OutOfBandRules {
		interrupt, err := rule.Eval(request)
		if err != nil {
			return nil, fmt.Errorf("unable to process inband rule %s : %s", rule.GetDisplayName(), err)
		}
		if interrupt != nil {
			return interrupt, nil
		}
	}
	return nil, nil
}
