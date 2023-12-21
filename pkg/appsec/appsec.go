package appsec

import (
	"fmt"
	"os"
	"regexp"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

const (
	hookOnLoad = iota
	hookPreEval
	hookPostEval
	hookOnMatch
)

func (h *Hook) Build(hookStage int) error {

	ctx := map[string]interface{}{}
	switch hookStage {
	case hookOnLoad:
		ctx = GetOnLoadEnv(&AppsecRuntimeConfig{})
	case hookPreEval:
		ctx = GetPreEvalEnv(&AppsecRuntimeConfig{}, &ParsedRequest{})
	case hookPostEval:
		ctx = GetPostEvalEnv(&AppsecRuntimeConfig{}, &ParsedRequest{})
	case hookOnMatch:
		ctx = GetOnMatchEnv(&AppsecRuntimeConfig{}, &ParsedRequest{}, types.Event{})
	}
	opts := exprhelpers.GetExprOptions(ctx)
	if h.Filter != "" {
		program, err := expr.Compile(h.Filter, opts...) //FIXME: opts
		if err != nil {
			return fmt.Errorf("unable to compile filter %s : %w", h.Filter, err)
		}
		h.FilterExpr = program
	}
	for _, apply := range h.Apply {
		program, err := expr.Compile(apply, opts...)
		if err != nil {
			return fmt.Errorf("unable to compile apply %s : %w", apply, err)
		}
		h.ApplyExpr = append(h.ApplyExpr, program)
	}
	return nil
}

type AppsecTempResponse struct {
	InBandInterrupt    bool
	OutOfBandInterrupt bool
	Action             string //allow, deny, captcha, log
	HTTPResponseCode   int
	SendEvent          bool //do we send an internal event on rule match
	SendAlert          bool //do we send an alert on rule match
}

type AppsecSubEngineOpts struct {
	DisableBodyInspection    bool `yaml:"disable_body_inspection"`
	RequestBodyInMemoryLimit *int `yaml:"request_body_in_memory_limit"`
}

// runtime version of AppsecConfig
type AppsecRuntimeConfig struct {
	Name           string
	OutOfBandRules []AppsecCollection

	InBandRules []AppsecCollection

	DefaultRemediation        string
	RemediationByTag          map[string]string //Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME
	RemediationById           map[int]string
	CompiledOnLoad            []Hook
	CompiledPreEval           []Hook
	CompiledPostEval          []Hook
	CompiledOnMatch           []Hook
	CompiledVariablesTracking []*regexp.Regexp
	Config                    *AppsecConfig
	//CorazaLogger              debuglog.Logger

	//those are ephemeral, created/destroyed with every req
	OutOfBandTx ExtendedTransaction //is it a good idea ?
	InBandTx    ExtendedTransaction //is it a good idea ?
	Response    AppsecTempResponse
	//should we store matched rules here ?

	Logger *log.Entry

	//Set by on_load to ignore some rules on loading
	DisabledInBandRuleIds   []int
	DisabledInBandRulesTags []string //Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME

	DisabledOutOfBandRuleIds   []int
	DisabledOutOfBandRulesTags []string //Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME
}

type AppsecConfig struct {
	Name               string              `yaml:"name"`
	OutOfBandRules     []string            `yaml:"outofband_rules"`
	InBandRules        []string            `yaml:"inband_rules"`
	DefaultRemediation string              `yaml:"default_remediation"`
	DefaultPassAction  string              `yaml:"default_pass_action"`
	BlockedHTTPCode    int                 `yaml:"blocked_http_code"`
	PassedHTTPCode     int                 `yaml:"passed_http_code"`
	OnLoad             []Hook              `yaml:"on_load"`
	PreEval            []Hook              `yaml:"pre_eval"`
	PostEval           []Hook              `yaml:"post_eval"`
	OnMatch            []Hook              `yaml:"on_match"`
	VariablesTracking  []string            `yaml:"variables_tracking"`
	InbandOptions      AppsecSubEngineOpts `yaml:"inband_options"`
	OutOfBandOptions   AppsecSubEngineOpts `yaml:"outofband_options"`

	LogLevel *log.Level `yaml:"log_level"`
	Logger   *log.Entry `yaml:"-"`
}

func (w *AppsecRuntimeConfig) ClearResponse() {
	log.Debugf("#-> %p", w)
	w.Response = AppsecTempResponse{}
	log.Debugf("-> %p", w.Config)
	w.Response.Action = w.Config.DefaultPassAction
	w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
	w.Response.SendEvent = true
	w.Response.SendAlert = true
}

func (wc *AppsecConfig) LoadByPath(file string) error {

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
		lvl := wc.Logger.Logger.GetLevel()
		wc.LogLevel = &lvl
	}
	wc.Logger = wc.Logger.Dup().WithField("name", wc.Name)
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

func (wc *AppsecConfig) Load(configName string) error {
	appsecConfigs := hub.GetItemMap(cwhub.APPSEC_CONFIGS)

	for _, hubAppsecConfigItem := range appsecConfigs {
		if !hubAppsecConfigItem.State.Installed {
			continue
		}
		if hubAppsecConfigItem.Name != configName {
			continue
		}
		wc.Logger.Infof("loading %s", hubAppsecConfigItem.State.LocalPath)
		err := wc.LoadByPath(hubAppsecConfigItem.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to load appsec-config %s : %s", hubAppsecConfigItem.State.LocalPath, err)
		}
		return nil
	}

	return fmt.Errorf("no appsec-config found for %s", configName)
}

func (wc *AppsecConfig) GetDataDir() string {
	return hub.GetDataDir()
}

func (wc *AppsecConfig) Build() (*AppsecRuntimeConfig, error) {
	ret := &AppsecRuntimeConfig{Logger: wc.Logger.WithField("component", "appsec_runtime_config")}
	ret.Name = wc.Name
	ret.Config = wc
	ret.DefaultRemediation = wc.DefaultRemediation

	wc.Logger.Tracef("Loading config %+v", wc)
	//load rules
	for _, rule := range wc.OutOfBandRules {
		wc.Logger.Infof("loading outofband rule %s", rule)
		collections, err := LoadCollection(rule, wc.Logger.WithField("component", "appsec_collection_loader"))
		if err != nil {
			return nil, fmt.Errorf("unable to load outofband rule %s : %s", rule, err)
		}
		ret.OutOfBandRules = append(ret.OutOfBandRules, collections...)
	}

	wc.Logger.Infof("Loaded %d outofband rules", len(ret.OutOfBandRules))
	for _, rule := range wc.InBandRules {
		wc.Logger.Infof("loading inband rule %s", rule)
		collections, err := LoadCollection(rule, wc.Logger.WithField("component", "appsec_collection_loader"))
		if err != nil {
			return nil, fmt.Errorf("unable to load inband rule %s : %s", rule, err)
		}
		ret.InBandRules = append(ret.InBandRules, collections...)
	}

	wc.Logger.Infof("Loaded %d inband rules", len(ret.InBandRules))

	//load hooks
	for _, hook := range wc.OnLoad {
		err := hook.Build(hookOnLoad)
		if err != nil {
			return nil, fmt.Errorf("unable to build on_load hook : %s", err)
		}
		ret.CompiledOnLoad = append(ret.CompiledOnLoad, hook)
	}

	for _, hook := range wc.PreEval {
		err := hook.Build(hookPreEval)
		if err != nil {
			return nil, fmt.Errorf("unable to build pre_eval hook : %s", err)
		}
		ret.CompiledPreEval = append(ret.CompiledPreEval, hook)
	}

	for _, hook := range wc.PostEval {
		err := hook.Build(hookPostEval)
		if err != nil {
			return nil, fmt.Errorf("unable to build post_eval hook : %s", err)
		}
		ret.CompiledPostEval = append(ret.CompiledPostEval, hook)
	}

	for _, hook := range wc.OnMatch {
		err := hook.Build(hookOnMatch)
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

func (w *AppsecRuntimeConfig) ProcessOnLoadRules() error {
	for _, rule := range w.CompiledOnLoad {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetOnLoadEnv(w), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec on_load filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Debugf("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		for _, applyExpr := range rule.ApplyExpr {
			_, err := exprhelpers.Run(applyExpr, GetOnLoadEnv(w), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				log.Errorf("unable to apply appsec on_load expr: %s", err)
				continue
			}
		}
	}
	return nil
}

func (w *AppsecRuntimeConfig) ProcessOnMatchRules(request *ParsedRequest, evt types.Event) error {

	for _, rule := range w.CompiledOnMatch {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetOnMatchEnv(w, request, evt), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec on_match filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Debugf("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		for _, applyExpr := range rule.ApplyExpr {
			_, err := exprhelpers.Run(applyExpr, GetOnMatchEnv(w, request, evt), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				log.Errorf("unable to apply appsec on_match expr: %s", err)
				continue
			}
		}
	}
	return nil
}

func (w *AppsecRuntimeConfig) ProcessPreEvalRules(request *ParsedRequest) error {
	for _, rule := range w.CompiledPreEval {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetPreEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec pre_eval filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Debugf("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		// here means there is no filter or the filter matched
		for _, applyExpr := range rule.ApplyExpr {
			_, err := exprhelpers.Run(applyExpr, GetPreEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				log.Errorf("unable to apply appsec pre_eval expr: %s", err)
				continue
			}
		}
	}

	return nil
}

func (w *AppsecRuntimeConfig) ProcessPostEvalRules(request *ParsedRequest) error {
	for _, rule := range w.CompiledPostEval {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetPostEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec post_eval filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					log.Debugf("filter didnt match")
					continue
				}
			default:
				log.Errorf("Filter must return a boolean, can't filter")
				continue
			}
		}
		// here means there is no filter or the filter matched
		for _, applyExpr := range rule.ApplyExpr {
			_, err := exprhelpers.Run(applyExpr, GetPostEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				log.Errorf("unable to apply appsec post_eval expr: %s", err)
				continue
			}
		}
	}

	return nil
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByID(id int) error {
	w.Logger.Debugf("removing inband rule %d", id)
	return w.InBandTx.RemoveRuleByIDWithError(id)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByID(id int) error {
	w.Logger.Debugf("removing outband rule %d", id)
	return w.OutOfBandTx.RemoveRuleByIDWithError(id)
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByTag(tag string) error {
	w.Logger.Debugf("removing inband rule with tag %s", tag)
	return w.InBandTx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByTag(tag string) error {
	w.Logger.Debugf("removing outband rule with tag %s", tag)
	return w.OutOfBandTx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByName(name string) error {
	tag := fmt.Sprintf("crowdsec-%s", name)
	w.Logger.Debugf("removing inband rule %s", tag)
	return w.InBandTx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByName(name string) error {
	tag := fmt.Sprintf("crowdsec-%s", name)
	w.Logger.Debugf("removing outband rule %s", tag)
	return w.OutOfBandTx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) CancelEvent() error {
	w.Logger.Debugf("canceling event")
	w.Response.SendEvent = false
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableInBandRuleByID(id int) error {
	w.DisabledInBandRuleIds = append(w.DisabledInBandRuleIds, id)
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableInBandRuleByName(name string) error {
	tagValue := fmt.Sprintf("crowdsec-%s", name)
	w.DisabledInBandRulesTags = append(w.DisabledInBandRulesTags, tagValue)
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableInBandRuleByTag(tag string) error {
	w.DisabledInBandRulesTags = append(w.DisabledInBandRulesTags, tag)
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableOutBandRuleByID(id int) error {
	w.DisabledOutOfBandRuleIds = append(w.DisabledOutOfBandRuleIds, id)
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableOutBandRuleByName(name string) error {
	tagValue := fmt.Sprintf("crowdsec-%s", name)
	w.DisabledOutOfBandRulesTags = append(w.DisabledOutOfBandRulesTags, tagValue)
	return nil
}

// Disable a rule at load time, meaning it will not run for any request
func (w *AppsecRuntimeConfig) DisableOutBandRuleByTag(tag string) error {
	w.DisabledOutOfBandRulesTags = append(w.DisabledOutOfBandRulesTags, tag)
	return nil
}

func (w *AppsecRuntimeConfig) SendEvent() error {
	w.Logger.Debugf("sending event")
	w.Response.SendEvent = true
	return nil
}

func (w *AppsecRuntimeConfig) SendAlert() error {
	w.Logger.Debugf("sending alert")
	w.Response.SendAlert = true
	return nil
}

func (w *AppsecRuntimeConfig) CancelAlert() error {
	w.Logger.Debugf("canceling alert")
	w.Response.SendAlert = false
	return nil
}

func (w *AppsecRuntimeConfig) SetActionByTag(tag string, action string) error {
	if w.RemediationByTag == nil {
		w.RemediationByTag = make(map[string]string)
	}
	w.Logger.Debugf("setting action of %s to %s", tag, action)
	w.RemediationByTag[tag] = action
	return nil
}

func (w *AppsecRuntimeConfig) SetActionByID(id int, action string) error {
	if w.RemediationById == nil {
		w.RemediationById = make(map[int]string)
	}
	w.Logger.Debugf("setting action of %d to %s", id, action)
	w.RemediationById[id] = action
	return nil
}

func (w *AppsecRuntimeConfig) SetActionByName(name string, action string) error {
	if w.RemediationByTag == nil {
		w.RemediationByTag = make(map[string]string)
	}
	tag := fmt.Sprintf("crowdsec-%s", name)
	w.Logger.Debugf("setting action of %s to %s", tag, action)
	w.RemediationByTag[tag] = action
	return nil
}

func (w *AppsecRuntimeConfig) SetAction(action string) error {
	//log.Infof("setting to %s", action)
	w.Logger.Debugf("setting action to %s", action)
	switch action {
	case "allow":
		w.Response.Action = action
		w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
		//@tko how should we handle this ? it seems bouncer only understand bans, but it might be misleading ?
	case "deny", "ban", "block":
		w.Response.Action = "ban"
	case "log":
		w.Response.Action = action
		w.Response.HTTPResponseCode = w.Config.PassedHTTPCode
	case "captcha":
		w.Response.Action = action
	default:
		return fmt.Errorf("unknown action %s", action)
	}
	return nil
}

func (w *AppsecRuntimeConfig) SetHTTPCode(code int) error {
	w.Logger.Debugf("setting http code to %d", code)
	w.Response.HTTPResponseCode = code
	return nil
}

type BodyResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status"`
}

func (w *AppsecRuntimeConfig) GenerateResponse(response AppsecTempResponse, logger *log.Entry) BodyResponse {
	resp := BodyResponse{}
	//if there is no interrupt, we should allow with default code
	if !response.InBandInterrupt {
		resp.Action = w.Config.DefaultPassAction
		resp.HTTPStatus = w.Config.PassedHTTPCode
		return resp
	}
	resp.Action = response.Action
	if resp.Action == "" {
		resp.Action = w.Config.DefaultRemediation
	}
	logger.Debugf("action is %s", resp.Action)

	resp.HTTPStatus = response.HTTPResponseCode
	if resp.HTTPStatus == 0 {
		resp.HTTPStatus = w.Config.BlockedHTTPCode
	}
	logger.Debugf("http status is %d", resp.HTTPStatus)
	return resp
}
