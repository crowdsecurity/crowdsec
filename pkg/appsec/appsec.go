package appsec

import (
	"fmt"
	"net/http"
	"os"
	"regexp"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

const (
	BanRemediation     = "ban"
	CaptchaRemediation = "captcha"
	AllowRemediation   = "allow"
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
		program, err := expr.Compile(h.Filter, opts...) // FIXME: opts
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
	InBandInterrupt         bool
	OutOfBandInterrupt      bool
	Action                  string // allow, deny, captcha, log
	UserHTTPResponseCode    int    // The response code to send to the user
	BouncerHTTPResponseCode int    // The response code to send to the remediation component
	SendEvent               bool   // do we send an internal event on rule match
	SendAlert               bool   // do we send an alert on rule match
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
	RemediationByTag          map[string]string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME
	RemediationById           map[int]string
	CompiledOnLoad            []Hook
	CompiledPreEval           []Hook
	CompiledPostEval          []Hook
	CompiledOnMatch           []Hook
	CompiledVariablesTracking []*regexp.Regexp
	Config                    *AppsecConfig
	// CorazaLogger              debuglog.Logger

	// those are ephemeral, created/destroyed with every req
	OutOfBandTx ExtendedTransaction // is it a good idea ?
	InBandTx    ExtendedTransaction // is it a good idea ?
	Response    AppsecTempResponse
	// should we store matched rules here ?

	Logger *log.Entry

	// Set by on_load to ignore some rules on loading
	DisabledInBandRuleIds   []int
	DisabledInBandRulesTags []string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME

	DisabledOutOfBandRuleIds   []int
	DisabledOutOfBandRulesTags []string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME
}

type AppsecConfig struct {
	Name                   string   `yaml:"name"`
	OutOfBandRules         []string `yaml:"outofband_rules"`
	InBandRules            []string `yaml:"inband_rules"`
	DefaultRemediation     string   `yaml:"default_remediation"`
	DefaultPassAction      string   `yaml:"default_pass_action"`
	BouncerBlockedHTTPCode int      `yaml:"blocked_http_code"`      // returned to the bouncer
	BouncerPassedHTTPCode  int      `yaml:"passed_http_code"`       // returned to the bouncer
	UserBlockedHTTPCode    int      `yaml:"user_blocked_http_code"` // returned to the user
	UserPassedHTTPCode     int      `yaml:"user_passed_http_code"`  // returned to the user

	OnLoad            []Hook              `yaml:"on_load"`
	PreEval           []Hook              `yaml:"pre_eval"`
	PostEval          []Hook              `yaml:"post_eval"`
	OnMatch           []Hook              `yaml:"on_match"`
	VariablesTracking []string            `yaml:"variables_tracking"`
	InbandOptions     AppsecSubEngineOpts `yaml:"inband_options"`
	OutOfBandOptions  AppsecSubEngineOpts `yaml:"outofband_options"`

	LogLevel *log.Level `yaml:"log_level"`
	Logger   *log.Entry `yaml:"-"`
}

func (w *AppsecRuntimeConfig) ClearResponse() {
	w.Response = AppsecTempResponse{}
	w.Response.Action = w.Config.DefaultPassAction
	w.Response.BouncerHTTPResponseCode = w.Config.BouncerPassedHTTPCode
	w.Response.UserHTTPResponseCode = w.Config.UserPassedHTTPCode
	w.Response.SendEvent = true
	w.Response.SendAlert = true
}

func (wc *AppsecConfig) SetUpLogger() {
	if wc.LogLevel == nil {
		lvl := wc.Logger.Logger.GetLevel()
		wc.LogLevel = &lvl
	}

	/* wc.Name is actually the datasource name.*/
	wc.Logger = wc.Logger.Dup().WithField("name", wc.Name)
	wc.Logger.Logger.SetLevel(*wc.LogLevel)
}

func (wc *AppsecConfig) LoadByPath(file string) error {
	wc.Logger.Debugf("loading config %s", file)

	yamlFile, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("unable to read file %s : %s", file, err)
	}

	//as  LoadByPath can be called several time, we append rules/hooks, but override other options
	var tmp AppsecConfig

	err = yaml.UnmarshalStrict(yamlFile, &tmp)
	if err != nil {
		return fmt.Errorf("unable to parse yaml file %s : %s", file, err)
	}

	if wc.Name == "" && tmp.Name != "" {
		wc.Name = tmp.Name
	}

	//We can append rules/hooks
	if tmp.OutOfBandRules != nil {
		wc.OutOfBandRules = append(wc.OutOfBandRules, tmp.OutOfBandRules...)
	}
	if tmp.InBandRules != nil {
		wc.InBandRules = append(wc.InBandRules, tmp.InBandRules...)
	}
	if tmp.OnLoad != nil {
		wc.OnLoad = append(wc.OnLoad, tmp.OnLoad...)
	}
	if tmp.PreEval != nil {
		wc.PreEval = append(wc.PreEval, tmp.PreEval...)
	}
	if tmp.PostEval != nil {
		wc.PostEval = append(wc.PostEval, tmp.PostEval...)
	}
	if tmp.OnMatch != nil {
		wc.OnMatch = append(wc.OnMatch, tmp.OnMatch...)
	}
	if tmp.VariablesTracking != nil {
		wc.VariablesTracking = append(wc.VariablesTracking, tmp.VariablesTracking...)
	}

	//override other options
	wc.LogLevel = tmp.LogLevel

	wc.DefaultRemediation = tmp.DefaultRemediation
	wc.DefaultPassAction = tmp.DefaultPassAction
	wc.BouncerBlockedHTTPCode = tmp.BouncerBlockedHTTPCode
	wc.BouncerPassedHTTPCode = tmp.BouncerPassedHTTPCode
	wc.UserBlockedHTTPCode = tmp.UserBlockedHTTPCode
	wc.UserPassedHTTPCode = tmp.UserPassedHTTPCode

	if tmp.InbandOptions.DisableBodyInspection {
		wc.InbandOptions.DisableBodyInspection = true
	}
	if tmp.InbandOptions.RequestBodyInMemoryLimit != nil {
		wc.InbandOptions.RequestBodyInMemoryLimit = tmp.InbandOptions.RequestBodyInMemoryLimit
	}
	if tmp.OutOfBandOptions.DisableBodyInspection {
		wc.OutOfBandOptions.DisableBodyInspection = true
	}
	if tmp.OutOfBandOptions.RequestBodyInMemoryLimit != nil {
		wc.OutOfBandOptions.RequestBodyInMemoryLimit = tmp.OutOfBandOptions.RequestBodyInMemoryLimit
	}

	return nil
}

func (wc *AppsecConfig) Load(configName string) error {
	item := hub.GetItem(cwhub.APPSEC_CONFIGS, configName)

	if item != nil && item.State.Installed {
		wc.Logger.Infof("loading %s", item.State.LocalPath)
		err := wc.LoadByPath(item.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to load appsec-config %s : %s", item.State.LocalPath, err)
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

	if wc.BouncerBlockedHTTPCode == 0 {
		wc.BouncerBlockedHTTPCode = http.StatusForbidden
	}
	if wc.BouncerPassedHTTPCode == 0 {
		wc.BouncerPassedHTTPCode = http.StatusOK
	}

	if wc.UserBlockedHTTPCode == 0 {
		wc.UserBlockedHTTPCode = http.StatusForbidden
	}
	if wc.UserPassedHTTPCode == 0 {
		wc.UserPassedHTTPCode = http.StatusOK
	}
	if wc.DefaultPassAction == "" {
		wc.DefaultPassAction = AllowRemediation
	}
	if wc.DefaultRemediation == "" {
		wc.DefaultRemediation = BanRemediation
	}

	// set the defaults
	switch wc.DefaultRemediation {
	case BanRemediation, CaptchaRemediation, AllowRemediation:
		// those are the officially supported remediation(s)
	default:
		wc.Logger.Warningf("default '%s' remediation of %s is none of [%s,%s,%s] ensure bouncer compatbility!", wc.DefaultRemediation, wc.Name, BanRemediation, CaptchaRemediation, AllowRemediation)
	}

	ret.Name = wc.Name
	ret.Config = wc
	ret.DefaultRemediation = wc.DefaultRemediation

	wc.Logger.Tracef("Loading config %+v", wc)
	// load rules
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

	// load hooks
	for _, hook := range wc.OnLoad {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for on_load hook : %s", hook.OnSuccess)
		}
		err := hook.Build(hookOnLoad)
		if err != nil {
			return nil, fmt.Errorf("unable to build on_load hook : %s", err)
		}
		ret.CompiledOnLoad = append(ret.CompiledOnLoad, hook)
	}

	for _, hook := range wc.PreEval {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for pre_eval hook : %s", hook.OnSuccess)
		}
		err := hook.Build(hookPreEval)
		if err != nil {
			return nil, fmt.Errorf("unable to build pre_eval hook : %s", err)
		}
		ret.CompiledPreEval = append(ret.CompiledPreEval, hook)
	}

	for _, hook := range wc.PostEval {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for post_eval hook : %s", hook.OnSuccess)
		}
		err := hook.Build(hookPostEval)
		if err != nil {
			return nil, fmt.Errorf("unable to build post_eval hook : %s", err)
		}
		ret.CompiledPostEval = append(ret.CompiledPostEval, hook)
	}

	for _, hook := range wc.OnMatch {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for on_match hook : %s", hook.OnSuccess)
		}
		err := hook.Build(hookOnMatch)
		if err != nil {
			return nil, fmt.Errorf("unable to build on_match hook : %s", err)
		}
		ret.CompiledOnMatch = append(ret.CompiledOnMatch, hook)
	}

	// variable tracking
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
	has_match := false
	for _, rule := range w.CompiledOnLoad {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetOnLoadEnv(w), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec on_load filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					w.Logger.Debugf("filter didnt match")
					continue
				}
			default:
				w.Logger.Errorf("Filter must return a boolean, can't filter")
				continue
			}
			has_match = true
		}
		for _, applyExpr := range rule.ApplyExpr {
			o, err := exprhelpers.Run(applyExpr, GetOnLoadEnv(w), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				w.Logger.Errorf("unable to apply appsec on_load expr: %s", err)
				continue
			}
			switch t := o.(type) {
			case error:
				w.Logger.Errorf("unable to apply appsec on_load expr: %s", t)
				continue
			default:
			}
		}
		if has_match && rule.OnSuccess == "break" {
			break
		}
	}
	return nil
}

func (w *AppsecRuntimeConfig) ProcessOnMatchRules(request *ParsedRequest, evt types.Event) error {
	has_match := false
	for _, rule := range w.CompiledOnMatch {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetOnMatchEnv(w, request, evt), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec on_match filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					w.Logger.Debugf("filter didnt match")
					continue
				}
			default:
				w.Logger.Errorf("Filter must return a boolean, can't filter")
				continue
			}
			has_match = true
		}
		for _, applyExpr := range rule.ApplyExpr {
			o, err := exprhelpers.Run(applyExpr, GetOnMatchEnv(w, request, evt), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				w.Logger.Errorf("unable to apply appsec on_match expr: %s", err)
				continue
			}
			switch t := o.(type) {
			case error:
				w.Logger.Errorf("unable to apply appsec on_match expr: %s", t)
				continue
			default:
			}
		}
		if has_match && rule.OnSuccess == "break" {
			break
		}
	}
	return nil
}

func (w *AppsecRuntimeConfig) ProcessPreEvalRules(request *ParsedRequest) error {
	has_match := false
	for _, rule := range w.CompiledPreEval {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetPreEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec pre_eval filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					w.Logger.Debugf("filter didnt match")
					continue
				}
			default:
				w.Logger.Errorf("Filter must return a boolean, can't filter")
				continue
			}
			has_match = true
		}
		// here means there is no filter or the filter matched
		for _, applyExpr := range rule.ApplyExpr {
			o, err := exprhelpers.Run(applyExpr, GetPreEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				w.Logger.Errorf("unable to apply appsec pre_eval expr: %s", err)
				continue
			}
			switch t := o.(type) {
			case error:
				w.Logger.Errorf("unable to apply appsec pre_eval expr: %s", t)
				continue
			default:
			}
		}
		if has_match && rule.OnSuccess == "break" {
			break
		}
	}

	return nil
}

func (w *AppsecRuntimeConfig) ProcessPostEvalRules(request *ParsedRequest) error {
	has_match := false
	for _, rule := range w.CompiledPostEval {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, GetPostEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec post_eval filter %s : %w", rule.Filter, err)
			}
			switch t := output.(type) {
			case bool:
				if !t {
					w.Logger.Debugf("filter didnt match")
					continue
				}
			default:
				w.Logger.Errorf("Filter must return a boolean, can't filter")
				continue
			}
			has_match = true
		}
		// here means there is no filter or the filter matched
		for _, applyExpr := range rule.ApplyExpr {
			o, err := exprhelpers.Run(applyExpr, GetPostEvalEnv(w, request), w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				w.Logger.Errorf("unable to apply appsec post_eval expr: %s", err)
				continue
			}

			switch t := o.(type) {
			case error:
				w.Logger.Errorf("unable to apply appsec post_eval expr: %s", t)
				continue
			default:
			}
		}
		if has_match && rule.OnSuccess == "break" {
			break
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
	// log.Infof("setting to %s", action)
	w.Logger.Debugf("setting action to %s", action)
	w.Response.Action = action
	return nil
}

func (w *AppsecRuntimeConfig) SetHTTPCode(code int) error {
	w.Logger.Debugf("setting http code to %d", code)
	w.Response.UserHTTPResponseCode = code
	return nil
}

type BodyResponse struct {
	Action     string `json:"action"`
	HTTPStatus int    `json:"http_status"`
}

func (w *AppsecRuntimeConfig) GenerateResponse(response AppsecTempResponse, logger *log.Entry) (int, BodyResponse) {
	var bouncerStatusCode int

	resp := BodyResponse{Action: response.Action}
	if response.Action == AllowRemediation {
		resp.HTTPStatus = w.Config.UserPassedHTTPCode
		bouncerStatusCode = w.Config.BouncerPassedHTTPCode
	} else { // ban, captcha and anything else
		resp.HTTPStatus = response.UserHTTPResponseCode
		if resp.HTTPStatus == 0 {
			resp.HTTPStatus = w.Config.UserBlockedHTTPCode
		}
		bouncerStatusCode = response.BouncerHTTPResponseCode
		if bouncerStatusCode == 0 {
			bouncerStatusCode = w.Config.BouncerBlockedHTTPCode
		}
	}

	return bouncerStatusCode, resp
}
