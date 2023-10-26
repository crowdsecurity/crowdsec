package waf

import (
	"fmt"
	"os"
	"regexp"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type Hook struct {
	Filter     string      `yaml:"filter"`
	FilterExpr *vm.Program `yaml:"-"`

	OnSuccess string        `yaml:"on_success"`
	Apply     []string      `yaml:"apply"`
	ApplyExpr []*vm.Program `yaml:"-"`
}

// @tko : todo - debug mode
func (h *Hook) Build() error {

	if h.Filter != "" {
		program, err := expr.Compile(h.Filter) //FIXME: opts
		if err != nil {
			return fmt.Errorf("unable to compile filter %s : %w", h.Filter, err)
		}
		h.FilterExpr = program
	}
	for _, apply := range h.Apply {
		program, err := expr.Compile(apply, GetExprWAFOptions(GetHookEnv(&WaapRuntimeConfig{}, ParsedRequest{}))...)
		if err != nil {
			return fmt.Errorf("unable to compile apply %s : %w", apply, err)
		}
		h.ApplyExpr = append(h.ApplyExpr, program)
	}
	return nil
}

type WaapTempResponse struct {
	InBandInterrupt    bool
	OutOfBandInterrupt bool
	Action             string //allow, deny, captcha, log
	HTTPResponseCode   int
	SendEvent          bool //do we send an internal event on rule match
}

type WaapSubEngineOpts struct {
	DisableBodyInspection    bool `yaml:"disable_body_inspection"`
	RequestBodyInMemoryLimit *int `yaml:"request_body_in_memory_limit"`
}

// runtime version of WaapConfig
type WaapRuntimeConfig struct {
	Name           string
	OutOfBandRules []WaapCollection

	InBandRules []WaapCollection

	DefaultRemediation        string
	CompiledOnLoad            []Hook
	CompiledPreEval           []Hook
	CompiledOnMatch           []Hook
	CompiledVariablesTracking []*regexp.Regexp
	Config                    *WaapConfig
	//CorazaLogger              debuglog.Logger

	//those are ephemeral, created/destroyed with every req
	OutOfBandTx ExtendedTransaction //is it a good idea ?
	InBandTx    ExtendedTransaction //is it a good idea ?
	Response    WaapTempResponse
	//should we store matched rules here ?

}

type WaapConfig struct {
	Name               string            `yaml:"name"`
	OutOfBandRules     []string          `yaml:"outofband_rules"`
	InBandRules        []string          `yaml:"inband_rules"`
	DefaultRemediation string            `yaml:"default_remediation"`
	DefaultPassAction  string            `yaml:"default_pass_action"`
	BlockedHTTPCode    int               `yaml:"blocked_http_code"`
	PassedHTTPCode     int               `yaml:"passed_http_code"`
	OnLoad             []Hook            `yaml:"on_load"`
	PreEval            []Hook            `yaml:"pre_eval"`
	OnMatch            []Hook            `yaml:"on_match"`
	VariablesTracking  []string          `yaml:"variables_tracking"`
	InbandOptions      WaapSubEngineOpts `yaml:"inband_options"`
	OutOfBandOptions   WaapSubEngineOpts `yaml:"outofband_options"`

	LogLevel *log.Level `yaml:"log_level"`
	Logger   *log.Entry `yaml:"-"`
}

func (w *WaapRuntimeConfig) ClearResponse() {
	log.Debugf("#-> %p", w)
	w.Response = WaapTempResponse{}
	log.Debugf("-> %p", w.Config)
	w.Response.Action = w.Config.DefaultPassAction
	w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
	w.Response.SendEvent = true
}

func (wc *WaapConfig) Load(file string) error {

	wc.Logger.Debugf("loading config %s", file)

	yamlFile, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read file %s : %s", file, err)
	}
	err = yaml.UnmarshalStrict(yamlFile, wc)
	if err != nil {
		return fmt.Errorf("unable to parse yaml file %s : %s", file, err)
	}

	if wc.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}
	if wc.LogLevel == nil {
		lvl := log.InfoLevel
		wc.LogLevel = &lvl
	}
	wc.Logger = wc.Logger.WithField("name", wc.Name)
	wc.Logger.Logger.SetLevel(*wc.LogLevel)
	if wc.DefaultRemediation == "" {
		return fmt.Errorf("default_remediation cannot be empty")
	}
	switch wc.DefaultRemediation {
	case "ban", "captcha", "log":
		//those are the officially supported remediation(s)
	default:
		wc.Logger.Warningf("default '%s' remediation of %s is none of [ban,captcha,log] ensure bouncer compatbility!", wc.DefaultRemediation, file)
	}
	if wc.BlockedHTTPCode == 0 {
		wc.BlockedHTTPCode = 403
	}
	if wc.PassedHTTPCode == 0 {
		wc.PassedHTTPCode = 200
	}
	if wc.DefaultPassAction == "" {
		wc.DefaultPassAction = "allow"
	}
	return nil
}

func (wc *WaapConfig) Build() (*WaapRuntimeConfig, error) {
	ret := &WaapRuntimeConfig{}
	ret.Name = wc.Name
	ret.Config = wc
	ret.DefaultRemediation = wc.DefaultRemediation

	//load rules
	for _, rule := range wc.OutOfBandRules {
		wc.Logger.Infof("loading outofband rule %s", rule)
		collection, err := LoadCollection(rule)
		if err != nil {
			return nil, fmt.Errorf("unable to load outofband rule %s : %s", rule, err)
		}
		ret.OutOfBandRules = append(ret.OutOfBandRules, collection)
	}

	wc.Logger.Infof("Loaded %d outofband rules", len(ret.OutOfBandRules))
	for _, rule := range wc.InBandRules {
		wc.Logger.Infof("loading inband rule %s", rule)
		collection, err := LoadCollection(rule)
		if err != nil {
			return nil, fmt.Errorf("unable to load inband rule %s : %s", rule, err)
		}
		ret.InBandRules = append(ret.InBandRules, collection)
	}

	wc.Logger.Infof("Loaded %d inband rules", len(ret.InBandRules))

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

func (w *WaapRuntimeConfig) ProcessOnLoadRules() error {
	for _, rule := range w.CompiledOnMatch {
		if rule.FilterExpr != nil {
			output, err := expr.Run(rule.FilterExpr, GetHookEnv(w, ParsedRequest{}))
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
			_, err := expr.Run(applyExpr, GetHookEnv(w, ParsedRequest{}))
			if err != nil {
				log.Errorf("unable to apply filter: %s", err)
				continue
			}
		}
	}
	return nil
}

func (w *WaapRuntimeConfig) ProcessOnMatchRules(request ParsedRequest) error {

	for _, rule := range w.CompiledOnMatch {
		if rule.FilterExpr != nil {
			output, err := expr.Run(rule.FilterExpr, GetHookEnv(w, request))
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
				// "req":                   request,
				// "RemoveInbandRuleByID":  w.RemoveInbandRuleByID,
				// "RemoveOutbandRuleByID": w.RemoveOutbandRuleByID,
				// "SetAction":             response.SetAction,
				// "SetRemediationByID":    response.SetRemediationByID,
				// "CancelEvent":           response.CancelEvent,
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
			output, err := expr.Run(rule.FilterExpr, GetHookEnv(w, request))
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
			_, err := expr.Run(applyExpr, GetHookEnv(w, request))
			if err != nil {
				log.Errorf("unable to apply filter: %s", err)
				continue
			}
		}
	}

	return nil
}

/* @sbl / @tko
add the helpers to:
 - remove by id-range
 - remove by tag
 - set remediation by tag/id-range

*/

func (w *WaapRuntimeConfig) RemoveInbandRuleByID(id int) error {
	return w.InBandTx.RemoveRuleByIDWithError(id)
}

func (w *WaapRuntimeConfig) CancelEvent() error {
	w.Response.SendEvent = false
	return nil
}

func (w *WaapRuntimeConfig) SetActionByTag(tag string, action string) error {
	panic("not implemented")
	return nil
}

func (w *WaapRuntimeConfig) SetActionByID(id int, action string) error {
	panic("not implemented")
	return nil
}

func (w *WaapRuntimeConfig) RemoveOutbandRuleByID(id int) error {
	return w.OutOfBandTx.RemoveRuleByIDWithError(id)
}

func (w *WaapRuntimeConfig) SetAction(action string) error {
	//log.Infof("setting to %s", action)
	switch action {
	case "allow":
		w.Response.Action = action
		w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
		//@tko how should we handle this ? it seems bouncer only understand bans, but it might be misleading ?
	case "deny", "ban", "block":
		w.Response.Action = "ban"
		w.Response.HTTPResponseCode = w.Config.BlockedHTTPCode
	case "log":
		w.Response.Action = action
		w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
	case "captcha":
		w.Response.Action = action
		w.Response.HTTPResponseCode = w.Config.BlockedHTTPCode
	default:
		return fmt.Errorf("unknown action %s", action)
	}
	return nil

}

func (w *WaapRuntimeConfig) SetHTTPCode(code int) error {
	w.Response.HTTPResponseCode = code
	return nil
}

type BodyResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status"`
}

func (w *WaapRuntimeConfig) GenerateResponse(interrupted bool) BodyResponse {
	resp := BodyResponse{}
	//if there is no interrupt, we should allow with default code
	if !interrupted {
		resp.Action = w.Config.DefaultPassAction
		resp.HTTPStatus = w.Config.PassedHTTPCode
		return resp
	}
	resp.Action = w.Config.DefaultRemediation
	resp.HTTPStatus = w.Config.BlockedHTTPCode

	return resp
}
