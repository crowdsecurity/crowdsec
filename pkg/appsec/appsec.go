package appsec

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type Hook struct {
	Filter     string      `yaml:"filter"`
	FilterExpr *vm.Program `yaml:"-"`

	OnSuccess string        `yaml:"on_success"`
	Apply     []string      `yaml:"apply"`
	ApplyExpr []*vm.Program `yaml:"-"`
}

type hookStage int

const (
	hookOnLoad hookStage = iota
	hookPreEval
	hookPostEval
	hookOnMatch
)

func (s hookStage) String() string {
	switch s {
	case hookOnLoad:
		return "on_load"
	case hookPreEval:
		return "pre_eval"
	case hookPostEval:
		return "post_eval"
	case hookOnMatch:
		return "on_match"
	default:
		return "unknown"
	}
}

// PhaseHooks bundles the three phase-scoped hook lists (pre_eval, post_eval,
// on_match) that run during request evaluation. OnLoad is excluded because it
// runs once at startup and is not phase-scoped.
type PhaseHooks struct {
	PreEval  []Hook
	PostEval []Hook
	OnMatch  []Hook
}

// get returns the hook list for a given stage, or nil for stages that are not
// phase-scoped (hookOnLoad or unknown).
func (p *PhaseHooks) get(stage hookStage) []Hook {
	switch stage {
	case hookPreEval:
		return p.PreEval
	case hookPostEval:
		return p.PostEval
	case hookOnMatch:
		return p.OnMatch
	default:
		return nil
	}
}

const (
	BanRemediation       = "ban"
	CaptchaRemediation   = "captcha"
	AllowRemediation     = "allow"
	ChallengeRemediation = "challenge"
)

const bodyChallengeOK = `{"status":"ok"}`
const bodyChallengeFailed = `{"status":"failed"}`

type phase int

const (
	PhaseInBand phase = iota
	PhaseOutOfBand
)

func (h *Hook) Build(stage hookStage, patcher *appsecExprPatcher) error {
	ctx := map[string]any{}

	switch stage {
	case hookOnLoad:
		ctx = GetOnLoadEnv(&AppsecRuntimeConfig{})
	case hookPreEval:
		ctx = GetPreEvalEnv(&AppsecRuntimeConfig{}, &AppsecRequestState{}, &ParsedRequest{})
	case hookPostEval:
		ctx = GetPostEvalEnv(&AppsecRuntimeConfig{}, &AppsecRequestState{}, &ParsedRequest{})
	case hookOnMatch:
		ctx = GetOnMatchEnv(&AppsecRuntimeConfig{}, &AppsecRequestState{}, &ParsedRequest{}, pipeline.Event{})
	}

	opts := exprhelpers.GetExprOptions(ctx)
	if patcher != nil {
		opts = append(opts, expr.Patch(patcher))
	}
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
	Action                  string                // allow, deny, captcha, challenge, log
	UserHTTPResponseCode    int                   // The response code to send to the user
	UserHTTPBodyContent     string                // The body content to send to the user, only for challenge response
	UserHTTPCookies         []cookie.AppsecCookie // Raw Set-Cookie headers to send to the user.
	UserHeaders             map[string][]string   // Headers to send to the user
	BouncerHTTPResponseCode int                   // The response code to send to the remediation component
	SendEvent               bool                  // do we send an internal event on rule match
	SendAlert               bool                  // do we send an alert on rule match
}

type AppsecDropInfo struct {
	Reason       string
	Interruption *corazatypes.Interruption
}

type AppsecRequestState struct {
	Tx           ExtendedTransaction
	CurrentPhase phase
	Response     AppsecTempResponse

	InBandDrop    *AppsecDropInfo
	OutOfBandDrop *AppsecDropInfo

	PendingAction   *string
	PendingHTTPCode *int

	RequireChallenge    bool
	Fingerprint         *challenge.FingerprintData
	ChallengeDifficulty *int // per-request PoW difficulty override (nil = use runtime default)
}

func (s *AppsecRequestState) ResetResponse(cfg *AppsecConfig) {
	if cfg == nil {
		s.Response = AppsecTempResponse{}
		return
	}

	s.Response = AppsecTempResponse{}
	s.Response.Action = cfg.DefaultPassAction
	s.Response.BouncerHTTPResponseCode = cfg.BouncerPassedHTTPCode
	s.Response.UserHTTPResponseCode = cfg.UserPassedHTTPCode
	s.Response.SendEvent = true
	s.Response.SendAlert = true
	s.Response.UserHTTPBodyContent = ""
	s.Response.UserHTTPCookies = nil
	s.PendingAction = nil
	s.PendingHTTPCode = nil
	s.RequireChallenge = false
}

func (s *AppsecRequestState) DropInfo(request *ParsedRequest) *AppsecDropInfo {
	switch {
	case request != nil && request.IsInBand:
		return s.InBandDrop
	case request != nil && request.IsOutBand:
		return s.OutOfBandDrop
	default:
		return nil
	}
}

func (s *AppsecRequestState) ApplyPendingResponse() {
	if s.PendingAction != nil {
		s.Response.Action = *s.PendingAction
		s.PendingAction = nil
	}

	if s.PendingHTTPCode != nil {
		s.Response.UserHTTPResponseCode = *s.PendingHTTPCode
		s.PendingHTTPCode = nil
	}
}

type AppsecSubEngineOpts struct {
	DisableBodyInspection    bool `yaml:"disable_body_inspection"`
	RequestBodyInMemoryLimit *int `yaml:"request_body_in_memory_limit"`
}

// AppsecPhaseConfig holds configuration scoped to a specific phase (inband or outofband).
// Hooks defined here are automatically dispatched only during the corresponding phase.
type AppsecPhaseConfig struct {
	Rules             []string            `yaml:"rules"`
	OnMatch           []Hook              `yaml:"on_match"`
	PreEval           []Hook              `yaml:"pre_eval"`
	PostEval          []Hook              `yaml:"post_eval"`
	Options           AppsecSubEngineOpts `yaml:"options"`
	VariablesTracking []string            `yaml:"variables_tracking"`
}

// runtime version of AppsecConfig
type AppsecRuntimeConfig struct {
	Name           string
	OutOfBandRules []AppsecCollection

	InBandRules []AppsecCollection

	DefaultRemediation string
	RemediationByTag   map[string]string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME
	RemediationById    map[int]string

	CompiledOnLoad []Hook     // runs once at startup, not phase-scoped
	CommonHooks    PhaseHooks // apply to both phases
	InBandHooks    PhaseHooks // only run during in-band
	OutOfBandHooks PhaseHooks // only run during out-of-band

	CompiledVariablesTracking []*regexp.Regexp
	Config                    *AppsecConfig
	// CorazaLogger              debuglog.Logger

	Logger *log.Entry

	// Set by on_load to ignore some rules on loading
	DisabledInBandRuleIds   []int
	DisabledInBandRulesTags []string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME

	DisabledOutOfBandRuleIds   []int
	DisabledOutOfBandRulesTags []string // Also used for ByName, as the name (for modsec rules) is a tag crowdsec-NAME

	// True if at least one of the hooks use `RequireValidChallenge`
	NeedWASMVM       bool
	ChallengeRuntime *challenge.ChallengeRuntime
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

	InBand    *AppsecPhaseConfig `yaml:"inband"`
	OutOfBand *AppsecPhaseConfig `yaml:"outofband"`

	LogLevel *log.Level `yaml:"log_level"`
	Logger   *log.Entry `yaml:"-"`
}

func (w *AppsecRuntimeConfig) NewRequestState() AppsecRequestState {
	state := AppsecRequestState{}
	state.ResetResponse(w.Config)
	return state
}

func (w *AppsecRuntimeConfig) ClearResponse(state *AppsecRequestState) {
	state.ResetResponse(w.Config)
}

func (w *AppsecRuntimeConfig) DropRequest(state *AppsecRequestState, request *ParsedRequest, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "request dropped by drop helper"
	}

	interrupt := &corazatypes.Interruption{
		RuleID: 0,
		Action: "deny",
		Status: w.Config.UserBlockedHTTPCode,
		Data:   reason,
		Tags:   []string{"crowdsec:drop-request"},
	}

	switch {
	case request.IsInBand:
		if state.Tx.Tx == nil {
			return errors.New("inband transaction not initialized")
		}
		interrupt.Tags = append(interrupt.Tags, "crowdsec:drop-request:inband")
		state.InBandDrop = &AppsecDropInfo{Reason: reason, Interruption: interrupt}
		state.Response.InBandInterrupt = true
		state.Response.Action = w.DefaultRemediation
		state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
		state.Response.UserHTTPResponseCode = w.Config.UserBlockedHTTPCode
		state.Tx.Interrupt(interrupt)
		w.Logger.Debugf("drop request helper triggered for inband phase: %s", reason)
	case request.IsOutBand:
		if state.Tx.Tx == nil {
			return errors.New("outofband transaction not initialized")
		}
		interrupt.Tags = append(interrupt.Tags, "crowdsec:drop-request:outofband")
		state.OutOfBandDrop = &AppsecDropInfo{Reason: reason, Interruption: interrupt}
		state.Response.OutOfBandInterrupt = true
		state.Tx.Interrupt(interrupt)
		w.Logger.Debugf("drop request helper triggered for out-of-band phase: %s", reason)
	default:
		return errors.New("unable to determine request band for drop helper")
	}

	return nil
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
		return fmt.Errorf("unable to read file %s : %w", file, err)
	}

	// as  LoadByPath can be called several time, we append rules/hooks, but override other options
	var tmp AppsecConfig

	err = yaml.UnmarshalStrict(yamlFile, &tmp)
	if err != nil {
		return fmt.Errorf("unable to parse yaml file %s : %w", file, err)
	}

	// Normalize phase-scoped sections: merge rules, options, and variables_tracking
	// into flat fields. Hooks stay in the phase sections for Build() to compile separately.
	tmp.normalizePhaseScoped()

	if wc.Name == "" && tmp.Name != "" {
		wc.Name = tmp.Name
	}

	// We can append rules/hooks
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

	// Append phase-scoped hooks
	if tmp.InBand != nil {
		if wc.InBand == nil {
			wc.InBand = &AppsecPhaseConfig{}
		}

		wc.InBand.OnMatch = append(wc.InBand.OnMatch, tmp.InBand.OnMatch...)
		wc.InBand.PreEval = append(wc.InBand.PreEval, tmp.InBand.PreEval...)
		wc.InBand.PostEval = append(wc.InBand.PostEval, tmp.InBand.PostEval...)
	}

	if tmp.OutOfBand != nil {
		if wc.OutOfBand == nil {
			wc.OutOfBand = &AppsecPhaseConfig{}
		}

		wc.OutOfBand.OnMatch = append(wc.OutOfBand.OnMatch, tmp.OutOfBand.OnMatch...)
		wc.OutOfBand.PreEval = append(wc.OutOfBand.PreEval, tmp.OutOfBand.PreEval...)
		wc.OutOfBand.PostEval = append(wc.OutOfBand.PostEval, tmp.OutOfBand.PostEval...)
	}

	// override other options
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

// normalizePhaseScoped merges rules, options, and variables_tracking from
// phase-scoped sections (inband/outofband) into the flat top-level fields.
// Hooks are left in the phase sections for Build() to compile separately.
func (wc *AppsecConfig) normalizePhaseScoped() {
	if wc.InBand != nil {
		wc.InBandRules = append(wc.InBandRules, wc.InBand.Rules...)
		wc.InBand.Rules = nil

		if wc.InBand.Options.DisableBodyInspection {
			wc.InbandOptions.DisableBodyInspection = true
		}

		if wc.InBand.Options.RequestBodyInMemoryLimit != nil {
			wc.InbandOptions.RequestBodyInMemoryLimit = wc.InBand.Options.RequestBodyInMemoryLimit
		}

		wc.VariablesTracking = append(wc.VariablesTracking, wc.InBand.VariablesTracking...)
		wc.InBand.VariablesTracking = nil
	}

	if wc.OutOfBand != nil {
		wc.OutOfBandRules = append(wc.OutOfBandRules, wc.OutOfBand.Rules...)
		wc.OutOfBand.Rules = nil

		if wc.OutOfBand.Options.DisableBodyInspection {
			wc.OutOfBandOptions.DisableBodyInspection = true
		}

		if wc.OutOfBand.Options.RequestBodyInMemoryLimit != nil {
			wc.OutOfBandOptions.RequestBodyInMemoryLimit = wc.OutOfBand.Options.RequestBodyInMemoryLimit
		}

		wc.VariablesTracking = append(wc.VariablesTracking, wc.OutOfBand.VariablesTracking...)
		wc.OutOfBand.VariablesTracking = nil
	}
}

// buildHookList validates and compiles a list of hooks of the given stage.
func buildHookList(hooks []Hook, stage hookStage, patcher *appsecExprPatcher) ([]Hook, error) {
	var compiled []Hook

	for _, hook := range hooks {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for %s hook : %s", stage, hook.OnSuccess)
		}

		if err := hook.Build(stage, patcher); err != nil {
			return nil, fmt.Errorf("unable to build %s hook : %w", stage, err)
		}

		compiled = append(compiled, hook)
	}

	return compiled, nil
}

// buildPhaseHooks compiles pre_eval / post_eval / on_match hook lists into a
// PhaseHooks. phaseName is only used to wrap errors ("" for the shared section).
func buildPhaseHooks(phaseName string, pre, post, onMatch []Hook, patcher *appsecExprPatcher) (PhaseHooks, error) {
	var (
		out PhaseHooks
		err error
	)

	wrap := func(e error) error {
		if phaseName == "" || e == nil {
			return e
		}
		return fmt.Errorf("%s: %w", phaseName, e)
	}

	if out.PreEval, err = buildHookList(pre, hookPreEval, patcher); err != nil {
		return PhaseHooks{}, wrap(err)
	}

	if out.PostEval, err = buildHookList(post, hookPostEval, patcher); err != nil {
		return PhaseHooks{}, wrap(err)
	}

	if out.OnMatch, err = buildHookList(onMatch, hookOnMatch, patcher); err != nil {
		return PhaseHooks{}, wrap(err)
	}

	return out, nil
}

func (wc *AppsecConfig) Load(configName string, hub *cwhub.Hub) error {
	item := hub.GetItem(cwhub.APPSEC_CONFIGS, configName)

	if item != nil && item.State.IsInstalled() {
		wc.Logger.Infof("loading %s", item.State.LocalPath)

		err := wc.LoadByPath(item.State.LocalPath)
		if err != nil {
			return fmt.Errorf("unable to load appsec-config %s : %s", item.State.LocalPath, err)
		}

		return nil
	}

	return fmt.Errorf("no appsec-config found for %s", configName)
}

func (wc *AppsecConfig) Build(hub *cwhub.Hub) (*AppsecRuntimeConfig, error) {
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
	case BanRemediation, CaptchaRemediation, AllowRemediation, ChallengeRemediation:
		// those are the officially supported remediation(s)
	default:
		wc.Logger.Warningf("default '%s' remediation of %s is none of [%s,%s,%s,%s] ensure bouncer compatbility!", wc.DefaultRemediation, wc.Name, BanRemediation, CaptchaRemediation, AllowRemediation, ChallengeRemediation)
	}

	ret.Name = wc.Name
	ret.Config = wc
	ret.DefaultRemediation = wc.DefaultRemediation

	wc.Logger.Tracef("Loading config %+v", wc)
	// load rules
	for _, rule := range wc.OutOfBandRules {
		wc.Logger.Infof("loading outofband rule %s", rule)

		collections, err := LoadCollection(rule, wc.Logger.WithField("component", "appsec_collection_loader"), hub)
		if err != nil {
			return nil, fmt.Errorf("unable to load outofband rule %s : %s", rule, err)
		}

		ret.OutOfBandRules = append(ret.OutOfBandRules, collections...)
	}

	wc.Logger.Infof("Loaded %d outofband rules", len(ret.OutOfBandRules))

	for _, rule := range wc.InBandRules {
		wc.Logger.Infof("loading inband rule %s", rule)

		collections, err := LoadCollection(rule, wc.Logger.WithField("component", "appsec_collection_loader"), hub)
		if err != nil {
			return nil, fmt.Errorf("unable to load inband rule %s : %s", rule, err)
		}

		ret.InBandRules = append(ret.InBandRules, collections...)
	}

	wc.Logger.Infof("Loaded %d inband rules", len(ret.InBandRules))

	patcher := &appsecExprPatcher{}

	// load hooks
	var err error

	if ret.CompiledOnLoad, err = buildHookList(wc.OnLoad, hookOnLoad, nil); err != nil {
		return nil, err
	}

	if ret.CommonHooks, err = buildPhaseHooks("", wc.PreEval, wc.PostEval, wc.OnMatch, patcher); err != nil {
		return nil, err
	}

	if wc.InBand != nil {
		if ret.InBandHooks, err = buildPhaseHooks("inband",
			wc.InBand.PreEval, wc.InBand.PostEval, wc.InBand.OnMatch, patcher); err != nil {
			return nil, err
		}
	}

	if wc.OutOfBand != nil {
		if ret.OutOfBandHooks, err = buildPhaseHooks("outofband",
			wc.OutOfBand.PreEval, wc.OutOfBand.PostEval, wc.OutOfBand.OnMatch, patcher); err != nil {
			return nil, err
		}
	}

	// variable tracking
	for _, variable := range wc.VariablesTracking {
		compiledVariableRule, err := regexp.Compile(variable)
		if err != nil {
			return nil, fmt.Errorf("cannot compile variable regexp %s: %w", variable, err)
		}

		ret.CompiledVariablesTracking = append(ret.CompiledVariablesTracking, compiledVariableRule)
	}

	ret.NeedWASMVM = patcher.NeedWASMVM

	return ret, nil
}

// processHooks runs a list of compiled hooks with the given environment.
func (w *AppsecRuntimeConfig) processHooks(hooks []Hook, env map[string]interface{}, hookType string) error {
	has_match := false

	for _, rule := range hooks {
		if rule.FilterExpr != nil {
			output, err := exprhelpers.Run(rule.FilterExpr, env, w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				return fmt.Errorf("unable to run appsec %s filter %s : %w", hookType, rule.Filter, err)
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
			o, err := exprhelpers.Run(applyExpr, env, w.Logger, w.Logger.Level >= log.DebugLevel)
			if err != nil {
				w.Logger.Errorf("unable to apply appsec %s expr: %s", hookType, err)
				continue
			}

			switch t := o.(type) {
			case error:
				w.Logger.Errorf("unable to apply appsec %s expr: %s", hookType, t)
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

func (w *AppsecRuntimeConfig) ProcessOnLoadRules() error {
	return w.processHooks(w.CompiledOnLoad, GetOnLoadEnv(w), "on_load")
}

// runPhaseHooks runs the common hooks for the given stage, then dispatches to
// the in-band or out-of-band phase hooks depending on the request band.
func (w *AppsecRuntimeConfig) runPhaseHooks(stage hookStage, env map[string]interface{}, request *ParsedRequest) error {
	label := stage.String()

	if err := w.processHooks(w.CommonHooks.get(stage), env, label); err != nil {
		return err
	}

	switch {
	case request.IsInBand:
		return w.processHooks(w.InBandHooks.get(stage), env, label+"[inband]")
	case request.IsOutBand:
		return w.processHooks(w.OutOfBandHooks.get(stage), env, label+"[outofband]")
	}

	return nil
}

func (w *AppsecRuntimeConfig) ProcessOnMatchRules(state *AppsecRequestState, request *ParsedRequest, evt pipeline.Event) error {
	return w.runPhaseHooks(hookOnMatch, GetOnMatchEnv(w, state, request, evt), request)
}

func (w *AppsecRuntimeConfig) ProcessPreEvalRules(state *AppsecRequestState, request *ParsedRequest) error {
	return w.runPhaseHooks(hookPreEval, GetPreEvalEnv(w, state, request), request)
}

func (w *AppsecRuntimeConfig) ProcessPostEvalRules(state *AppsecRequestState, request *ParsedRequest) error {
	return w.runPhaseHooks(hookPostEval, GetPostEvalEnv(w, state, request), request)
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByID(state *AppsecRequestState, id int) error {
	if state.CurrentPhase != PhaseInBand {
		w.Logger.Warnf("cannot remove inband rule %d when not in inband phase", id)
		return nil
	}

	w.Logger.Debugf("removing inband rule %d", id)
	return state.Tx.RemoveRuleByIDWithError(id)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByID(state *AppsecRequestState, id int) error {
	if state.CurrentPhase != PhaseOutOfBand {
		w.Logger.Warnf("cannot remove outband rule %d when not in outband phase", id)
		return nil
	}

	w.Logger.Debugf("removing outband rule %d", id)
	return state.Tx.RemoveRuleByIDWithError(id)
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByTag(state *AppsecRequestState, tag string) error {
	if state.CurrentPhase != PhaseInBand {
		w.Logger.Warnf("cannot remove inband rule with tag %s when not in inband phase", tag)
		return nil
	}

	w.Logger.Debugf("removing inband rule with tag %s", tag)
	return state.Tx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByTag(state *AppsecRequestState, tag string) error {
	if state.CurrentPhase != PhaseOutOfBand {
		w.Logger.Warnf("cannot remove outband rule with tag %s when not in outband phase", tag)
		return nil
	}

	w.Logger.Debugf("removing outband rule with tag %s", tag)
	return state.Tx.RemoveRuleByTagWithError(tag)
}

func (w *AppsecRuntimeConfig) RemoveInbandRuleByName(state *AppsecRequestState, name string) error {
	if state.CurrentPhase != PhaseInBand {
		w.Logger.Warnf("cannot remove inband rule with name %s when not in inband phase", name)
		return nil
	}
	tag := fmt.Sprintf("crowdsec-%s", name)
	w.Logger.Debugf("removing inband rule %s", tag)
	return w.RemoveInbandRuleByTag(state, tag)
}

func (w *AppsecRuntimeConfig) RemoveOutbandRuleByName(state *AppsecRequestState, name string) error {
	if state.CurrentPhase != PhaseOutOfBand {
		w.Logger.Warnf("cannot remove outband rule with name %s when not in outband phase", name)
		return nil
	}
	tag := fmt.Sprintf("crowdsec-%s", name)
	w.Logger.Debugf("removing outband rule %s", tag)
	return w.RemoveOutbandRuleByTag(state, tag)
}

func (w *AppsecRuntimeConfig) CancelEvent(state *AppsecRequestState) error {
	w.Logger.Debugf("canceling event")
	state.Response.SendEvent = false

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

func (w *AppsecRuntimeConfig) SendEvent(state *AppsecRequestState) error {
	w.Logger.Debugf("sending event")
	state.Response.SendEvent = true
	return nil
}

func (w *AppsecRuntimeConfig) SendAlert(state *AppsecRequestState) error {
	w.Logger.Debugf("sending alert")
	state.Response.SendAlert = true
	return nil
}

func (w *AppsecRuntimeConfig) CancelAlert(state *AppsecRequestState) error {
	w.Logger.Debugf("canceling alert")
	state.Response.SendAlert = false
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

func (w *AppsecRuntimeConfig) SetAction(state *AppsecRequestState, action string) error {
	w.Logger.Debugf("setting action to %s", action)
	state.Response.Action = action
	return nil
}

func (w *AppsecRuntimeConfig) SetHTTPCode(state *AppsecRequestState, code int) error {
	w.Logger.Debugf("setting http code to %d", code)
	state.Response.UserHTTPResponseCode = code
	return nil
}

func (w *AppsecRuntimeConfig) SetChallengeBody(state *AppsecRequestState, content string) error {
	w.Logger.Debugf("setting challenge body content")
	state.Response.UserHTTPBodyContent = content
	return nil
}

func (w *AppsecRuntimeConfig) SetChallengeCookie(state *AppsecRequestState, cookie cookie.AppsecCookie) error {
	w.Logger.Debugf("adding challenge cookie")
	state.Response.UserHTTPCookies = append(state.Response.UserHTTPCookies, cookie)
	return nil
}

func (w *AppsecRuntimeConfig) SetChallengeHeader(state *AppsecRequestState, name string, value string) error {
	w.Logger.Debugf("adding challenge headers")
	if state.Response.UserHeaders == nil {
		state.Response.UserHeaders = make(map[string][]string)
	}
	state.Response.UserHeaders[name] = append(state.Response.UserHeaders[name], value)
	return nil
}

func (w *AppsecRuntimeConfig) setChallengeResponse(state *AppsecRequestState, code int, body string, headers map[string]string, cookie *cookie.AppsecCookie) error {
	w.SetAction(state, ChallengeRemediation)
	w.SetHTTPCode(state, code)
	// FIXME: don't do this here, should be handled the same way as a block
	state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
	w.SetChallengeBody(state, body)
	for name, value := range headers {
		w.SetChallengeHeader(state, name, value)
	}
	if cookie != nil {
		w.SetChallengeCookie(state, *cookie)
	}
	state.RequireChallenge = true
	return nil
}

// SetChallengeDifficulty sets the default PoW difficulty on the runtime (used from on_load).
func (w *AppsecRuntimeConfig) SetChallengeDifficulty(level string) error {
	if w.ChallengeRuntime == nil {
		return fmt.Errorf("challenge runtime not initialized")
	}

	return w.ChallengeRuntime.SetDifficulty(level)
}

// SetChallengeDifficultyPerRequest sets a per-request PoW difficulty override (used from pre_eval/post_eval).
func (w *AppsecRuntimeConfig) SetChallengeDifficultyPerRequest(state *AppsecRequestState, level string) error {
	bits, err := challenge.DifficultyFromLevel(level)
	if err != nil {
		return err
	}

	state.ChallengeDifficulty = &bits

	return nil
}

func (w *AppsecRuntimeConfig) SendChallenge(state *AppsecRequestState, request *ParsedRequest) error {
	w.Logger.Debugf("sending challenge")

	if w.ChallengeRuntime == nil {
		return fmt.Errorf("challenge runtime not initialized")
	}

	// Check if the request has a challenge response
	// If there's a challenge response, validate it
	// If ok, generate cookie + return it (challenge remediation + meta refresh + cookie)
	// If bad, return challenge page
	// Finally, check for the challenge cookie
	// If it's valid, just return
	// If not, return the challenge HTML page

	// Serve the PoW worker script (plain JS, not obfuscated)
	if request.HTTPRequest.URL.Path == challenge.ChallengePowWorkerPath {
		return w.setChallengeResponse(state, http.StatusOK, challenge.PowWorkerJS, map[string]string{"Content-Type": "application/javascript", "Cache-Control": "public, max-age=3600"}, nil)
	}

	if request.HTTPRequest.URL.Path == challenge.ChallengeSubmitPath && request.HTTPRequest.Method == http.MethodPost {
		w.Logger.Debugf("Validating challenge response")
		body := bodyChallengeOK
		cookie, _, err := w.ChallengeRuntime.ValidateChallengeResponse(request.HTTPRequest, request.Body)
		if err != nil {
			// TODO: find a way to propagate an event to the LP for use in scenarios
			w.Logger.Errorf("Challenge validation failed: %s", err)
			body = bodyChallengeFailed
		}
		return w.setChallengeResponse(state, http.StatusOK, body, map[string]string{"Content-Type": "application/json", "Cache-Control": "no-cache, no-store"}, cookie)
	}

	httpCookie, err := request.HTTPRequest.Cookie(challenge.ChallengeCookieName)
	if err == nil {
		if fpData, validErr := w.ChallengeRuntime.ValidCookie(httpCookie, request.HTTPRequest.UserAgent()); validErr == nil {
			w.Logger.Debugf("valid challenge cookie found, setting fingerprint data in transaction")
			state.Fingerprint = fpData
			return nil
		}
	}

	w.Logger.Debugf("no valid challenge cookie found")

	difficulty := 0 // 0 = use runtime default
	if state.ChallengeDifficulty != nil {
		difficulty = *state.ChallengeDifficulty
	}

	challengePage, err := w.ChallengeRuntime.GetChallengePage(request.HTTPRequest.UserAgent(), difficulty)
	if err != nil {
		return fmt.Errorf("unable to get challenge page: %w", err)
	}
	return w.setChallengeResponse(state, http.StatusOK, challengePage, map[string]string{"Content-Type": "text/html", "Cache-Control": "no-cache, no-store"}, nil)
}

/*func (w *AppsecRuntimeConfig) ValidateChallenge(state *AppsecRequestState, request *ParsedRequest, conditions ...bool) (*challenge.ChallengeMatcher, error) {

	httpCookie, err := request.HTTPRequest.Cookie(challenge.ChallengeCookieName)
	if err == nil && w.ChallengeRuntime != nil {
		if _, validErr := w.ChallengeRuntime.ValidCookie(httpCookie, request.HTTPRequest.UserAgent()); validErr == nil {
			w.Logger.Debugf("valid challenge cookie found, allowing request")
			return challenge.NewChallengeMatcher(true), nil
		}
	}

	if request.HTTPRequest.URL.Path != challenge.ChallengeSubmitPath || request.HTTPRequest.Method != http.MethodPost {
		// If not a challenge submission, consider it valid
		//
		return challenge.NewChallengeMatcher(true), nil
	}

	return challenge.NewChallengeMatcher(true), nil
}*/

type BodyResponse struct {
	Action          string              `json:"action"`
	HTTPStatus      int                 `json:"http_status"`
	UserBodyContent string              `json:"user_body_content,omitempty"`
	UserCookies     []string            `json:"user_cookies,omitempty"`
	UserHeaders     map[string][]string `json:"user_headers,omitempty"`
}

func (w *AppsecRuntimeConfig) GenerateResponse(response AppsecTempResponse, logger *log.Entry) (int, BodyResponse) {
	var bouncerStatusCode int

	resp := BodyResponse{Action: response.Action}

	//spew.Dump("Generating response", response)

	switch response.Action {
	case AllowRemediation:
		resp.HTTPStatus = w.Config.UserPassedHTTPCode
		bouncerStatusCode = w.Config.BouncerPassedHTTPCode
	case ChallengeRemediation:
		resp.UserBodyContent = response.UserHTTPBodyContent
		resp.UserCookies = make([]string, 0, len(response.UserHTTPCookies))
		for _, cookie := range response.UserHTTPCookies {
			resp.UserCookies = append(resp.UserCookies, cookie.String())
		}
		resp.UserHeaders = response.UserHeaders
		// Return code are handled the same way for challenge/ban/captcha
		// There's probably a less brittle way to do this, but falltrhough is easier
		fallthrough
	case BanRemediation, CaptchaRemediation:
		resp.HTTPStatus = response.UserHTTPResponseCode
		if resp.HTTPStatus == 0 {
			resp.HTTPStatus = w.Config.UserBlockedHTTPCode
		}
		bouncerStatusCode = response.BouncerHTTPResponseCode
		if bouncerStatusCode == 0 {
			bouncerStatusCode = w.Config.BouncerBlockedHTTPCode
		}
	default:
		// Custom remediations use the same status code logic as ban/captcha
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
