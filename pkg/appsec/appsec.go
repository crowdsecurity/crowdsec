package appsec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	corazatypes "github.com/corazawaf/coraza/v3/types"
	apivalidation "github.com/crowdsecurity/crowdsec/pkg/appsec/api_validation"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
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
	hookOnChallenge
	hookOnChallengeSubmit
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
	case hookOnChallenge:
		return "on_challenge"
	case hookOnChallengeSubmit:
		return "on_challenge_submit"
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

// bodyChallengeRejected is returned when an on_challenge_submit hook calls
// RejectSubmission to refuse cookie issuance after a cryptographically
// valid submission. The client-side JS handler renders a terminal "your
// browser was rejected" UI with no retry CTA (vs. "failed" which prompts
// a retry). The server-side reason string is logged but NOT echoed to
// the client to avoid leaking detection logic.
const bodyChallengeRejected = `{"status":"rejected"}`
const (
	// BodySizeActionDrop drops the request when the body exceeds the maximum size.
	BodySizeActionDrop = "drop"
	// BodySizeActionPartial reads the body up to the maximum size and processes it.
	BodySizeActionPartial = "partial"
	// BodySizeActionAllow processes the request without inspecting the body.
	BodySizeActionAllow = "allow"

	// DefaultMaxBodySize is the default maximum body size (10MB).
	DefaultMaxBodySize = int64(10 * 1024 * 1024)
)

type phase int

const (
	PhaseInBand phase = iota
	PhaseOutOfBand
)

func (h *Hook) Build(ctx context.Context, stage hookStage, patcher *appsecExprPatcher) error {
	env := map[string]any{}

	// Env builders for phase hooks dereference state (e.g. state.HookVars), so
	// we hand them a zero-value state with an initialized HookVars map for
	// compile-time expr setup. At runtime the real state is passed.
	placeholderState := &AppsecRequestState{HookVars: map[string]string{}}

	switch stage {
	case hookOnLoad:
		env = GetOnLoadEnv(&AppsecRuntimeConfig{})
	case hookPreEval:
		env = GetPreEvalEnv(ctx, &AppsecRuntimeConfig{}, placeholderState, &ParsedRequest{})
	case hookPostEval:
		env = GetPostEvalEnv(ctx, &AppsecRuntimeConfig{}, placeholderState, &ParsedRequest{})
	case hookOnMatch:
		env = GetOnMatchEnv(&AppsecRuntimeConfig{}, placeholderState, &ParsedRequest{}, pipeline.Event{})
	case hookOnChallenge:
		env = GetOnChallengeEnv(ctx, &AppsecRuntimeConfig{}, placeholderState, &ParsedRequest{})
	case hookOnChallengeSubmit:
		env = GetOnChallengeSubmitEnv(&AppsecRuntimeConfig{}, placeholderState, &ParsedRequest{})
	}

	opts := exprhelpers.GetExprOptions(env)
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

func (r AppsecTempResponse) Clone() AppsecTempResponse {
	clone := r
	if r.UserHeaders != nil {
		clone.UserHeaders = make(map[string][]string, len(r.UserHeaders))
		for k, v := range r.UserHeaders {
			clone.UserHeaders[k] = append([]string(nil), v...)
		}
	}
	if r.UserHTTPCookies != nil {
		clone.UserHTTPCookies = append([]cookie.AppsecCookie(nil), r.UserHTTPCookies...)
	}
	return clone
}

type AppsecDropInfo struct {
	Reason       string
	Interruption *corazatypes.Interruption
}

// SubmissionRejectInfo signals that an on_challenge_submit hook called
// RejectSubmission to refuse cookie issuance for a cryptographically valid
// submission. ProcessOnChallengeRules inspects this on the submit-path
// branch and, if set, serves bodyChallengeRejected with no Set-Cookie.
type SubmissionRejectInfo struct {
	Reason string
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
	CookiePowDifficulty int  // PoW difficulty proven by the client for the current cookie (0 if no/invalid cookie)
	ChallengeDifficulty *int // per-request PoW difficulty override (nil = use runtime default)

	// SubmissionRejection is set by RejectSubmission inside an
	// on_challenge_submit hook to refuse cookie issuance for the current
	// challenge submission. nil for any other phase / outcome.
	SubmissionRejection *SubmissionRejectInfo

	// ChallengeBypassed is set by GrantChallengeCookie to suppress later
	// SendChallenge calls in the same request. Per-request only; cleared
	// on ResetResponse. The bypass for subsequent requests is carried by
	// the allowlist cookie itself, not by this flag.
	ChallengeBypassed bool

	// HooksHalted is flipped by terminal hook actions (currently
	// RejectSubmission and the inline GrantChallengeCookie variant
	// exposed in on_challenge_submit) to short-circuit later rules in
	// the same phase. Without this, a `LogAccepted` rule following a
	// `RejectSubmission` rule with `filter: "true"` would emit a
	// contradictory accept-log line for an already-rejected submission.
	// Per-request only; cleared by ResetResponse.
	HooksHalted bool

	// LastMismatchReport caches the result of the EvaluateMismatches expr
	// closure for the current request, so repeated calls from a single
	// rule expression don't redo the work (or re-emit observability).
	// nil until the first call.
	LastMismatchReport *challenge.MismatchReport

	// HookVars is a per-request scratch space exposed to expr hooks as
	// `hook_vars`. Helpers (e.g. ValidateRequestWithSchema) publish string
	// values here so that later hook expressions — including the `apply`
	// block of the same hook — can read them. The map is allocated once in
	// NewRequestState, persists across in-band/out-of-band phases, and is
	// copied into pipeline.AppsecEvent.HookVars when an event is emitted.
	HookVars              map[string]string
	DisableBodyInspection bool
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
	s.SubmissionRejection = nil
	s.ChallengeBypassed = false
	s.HooksHalted = false
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

// BodySettings controls how oversized request bodies are handled.
type BodySettings struct {
	// MaxSize is the maximum allowed body size in bytes. Defaults to DefaultMaxBodySize (10MB).
	MaxSize int64 `yaml:"max_body_size"`
	// Action controls what happens when a body exceeds MaxSize:
	// "drop" (default) - block the request, "partial" - inspect up to MaxSize bytes, "allow" - skip body inspection.
	Action string `yaml:"body_size_exceeded_action"`
}

// AppsecPhaseConfig holds configuration scoped to a specific phase (inband or outofband).
// Hooks defined here are automatically dispatched only during the corresponding phase.
// on_challenge and on_challenge_submit are in-band only; setting them under
// `outofband:` is rejected at Build() time.
type AppsecPhaseConfig struct {
	Rules             []string            `yaml:"rules"`
	OnMatch           []Hook              `yaml:"on_match"`
	PreEval           []Hook              `yaml:"pre_eval"`
	PostEval          []Hook              `yaml:"post_eval"`
	OnChallenge       []Hook              `yaml:"on_challenge"`
	OnChallengeSubmit []Hook              `yaml:"on_challenge_submit"`
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

	CompiledOnLoad            []Hook     // runs once at startup, not phase-scoped
	CompiledOnChallenge       []Hook     // in-band only; runs before pre_eval
	CompiledOnChallengeSubmit []Hook     // in-band only; runs at /submit POST after validation
	CommonHooks               PhaseHooks // apply to both phases
	InBandHooks               PhaseHooks // only run during in-band
	OutOfBandHooks            PhaseHooks // only run during out-of-band

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

	// OutChan is the pipeline output channel challenge lifecycle events are sent
	// on, and Labels are the datasource labels stamped on those events. Both are
	// wired by the appsec datasource at startup; nil OutChan disables emission
	// (e.g. in unit tests with no datasource).
	OutChan chan pipeline.Event
	Labels  map[string]string

	// FingerprintDumpDir is the on-disk directory the DumpFingerprint
	FingerprintDumpDir string

	RequestValidator *apivalidation.RequestValidator
	DataDir          string
	// BodySettings controls how oversized request bodies are handled. Settable via on_load hooks.
	BodySettings BodySettings
}

// emitChallengeEvent builds and sends a challenge lifecycle event to the
// pipeline. It is a no-op when no output channel is wired. Challenge handling is
// an in-band concern, so we never emit during the out-of-band phase — a common
// pre_eval/post_eval hook calling SendChallenge() runs in both phases, and the
// out-of-band invocation is already a no-op for the client.
func (w *AppsecRuntimeConfig) emitChallengeEvent(request *ParsedRequest, info ChallengeEventInfo) {
	if w.OutChan == nil || !request.IsInBand {
		return
	}

	labels := prometheus.Labels{
		"source":        request.RemoteAddrNormalized,
		"appsec_engine": request.AppsecEngine,
	}

	switch info.Reason {
	case ChallengeReasonRequested:
		metrics.AppsecChallengeRequested.With(labels).Inc()
	case ChallengeReasonSubmitted:
		metrics.AppsecChallengeSubmitted.With(labels).Inc()
	case ChallengeReasonSolved:
		acceptedLabels := prometheus.Labels{
			"source":        labels["source"],
			"appsec_engine": labels["appsec_engine"],
			"kind":          "solved",
			"reason":        "", // regular submissions have no per-issue reason
		}
		metrics.AppsecChallengeAccepted.With(acceptedLabels).Inc()
	case ChallengeReasonFailed:
		rejectedLabels := prometheus.Labels{
			"source":        labels["source"],
			"appsec_engine": labels["appsec_engine"],
			"kind":          "protocol",
			"reason":        classifyProtocolErr(info.FailErr),
		}
		metrics.AppsecChallengeRejected.With(rejectedLabels).Inc()
	case ChallengeReasonRejected:
		rejectedLabels := prometheus.Labels{
			"source":        labels["source"],
			"appsec_engine": labels["appsec_engine"],
			"kind":          "submission",
			"reason":        info.FailReason,
		}
		metrics.AppsecChallengeRejected.With(rejectedLabels).Inc()
	}

	w.OutChan <- ChallengeEventFromRequest(request, w.Labels, request.UUID, info)
}

// classifyProtocolErr maps a challenge-validation error to one of a small
// closed vocabulary.
func classifyProtocolErr(err error) string {
	switch {
	case err == nil:
		return "other"
	case errors.Is(err, challenge.ErrChallengeHMAC):
		return "hmac"
	case errors.Is(err, challenge.ErrChallengeTicket):
		return "ticket"
	case errors.Is(err, challenge.ErrChallengePoW):
		return "pow"
	case errors.Is(err, challenge.ErrChallengeFields), errors.Is(err, challenge.ErrChallengePayload):
		return "payload"
	case errors.Is(err, challenge.ErrChallengeDifficulty):
		return "difficulty"
	default:
		return "other"
	}
}

// classifyCookieErr maps a ValidCookie error to one of a small closed
// vocabulary
func classifyCookieErr(err error) string {
	switch {
	case err == nil:
		return "other"
	case errors.Is(err, challenge.ErrCookieSignature):
		return "signature"
	case errors.Is(err, challenge.ErrCookiePayload), errors.Is(err, challenge.ErrCookieMalformed):
		return "payload"
	case errors.Is(err, challenge.ErrCookieExpired), errors.Is(err, challenge.ErrCookieVersion):
		return "epoch"
	default:
		return "other"
	}
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
	OnChallenge       []Hook              `yaml:"on_challenge"`
	OnChallengeSubmit []Hook              `yaml:"on_challenge_submit"`
	VariablesTracking []string            `yaml:"variables_tracking"`
	InbandOptions     AppsecSubEngineOpts `yaml:"inband_options"`
	OutOfBandOptions  AppsecSubEngineOpts `yaml:"outofband_options"`

	InBand    *AppsecPhaseConfig `yaml:"inband"`
	OutOfBand *AppsecPhaseConfig `yaml:"outofband"`

	// Challenge carries the WAF challenge / bot-detection runtime tuning.
	// All fields are optional; unset fields fall back to the runtime
	// defaults at NewChallengeRuntime time. When multiple appsec-configs
	// are loaded, each later config's non-nil fields override the earlier
	// values (see LoadByPath).
	Challenge *challenge.Config `yaml:"challenge"`

	LogLevel *log.Level `yaml:"log_level"`
	Logger   *log.Entry `yaml:"-"`
}

func (w *AppsecRuntimeConfig) NewRequestState() AppsecRequestState {
	state := AppsecRequestState{
		HookVars: make(map[string]string),
	}
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

	if tmp.OnChallenge != nil {
		wc.OnChallenge = append(wc.OnChallenge, tmp.OnChallenge...)
	}

	if tmp.OnChallengeSubmit != nil {
		wc.OnChallengeSubmit = append(wc.OnChallengeSubmit, tmp.OnChallengeSubmit...)
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
		wc.InBand.OnChallenge = append(wc.InBand.OnChallenge, tmp.InBand.OnChallenge...)
		wc.InBand.OnChallengeSubmit = append(wc.InBand.OnChallengeSubmit, tmp.InBand.OnChallengeSubmit...)
	}

	if tmp.OutOfBand != nil {
		if wc.OutOfBand == nil {
			wc.OutOfBand = &AppsecPhaseConfig{}
		}

		wc.OutOfBand.OnMatch = append(wc.OutOfBand.OnMatch, tmp.OutOfBand.OnMatch...)
		wc.OutOfBand.PreEval = append(wc.OutOfBand.PreEval, tmp.OutOfBand.PreEval...)
		wc.OutOfBand.PostEval = append(wc.OutOfBand.PostEval, tmp.OutOfBand.PostEval...)
		wc.OutOfBand.OnChallenge = append(wc.OutOfBand.OnChallenge, tmp.OutOfBand.OnChallenge...)
		wc.OutOfBand.OnChallengeSubmit = append(wc.OutOfBand.OnChallengeSubmit, tmp.OutOfBand.OnChallengeSubmit...)
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

	// Merge challenge tuning field by field so multiple appsec-configs can
	// each contribute a disjoint subset without one wiping out the others.
	// Each non-nil field in tmp overrides the corresponding field in wc.
	if tmp.Challenge != nil {
		if wc.Challenge == nil {
			wc.Challenge = &challenge.Config{}
		}
		wc.Challenge.MergeFrom(tmp.Challenge)
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
func buildHookList(ctx context.Context, hooks []Hook, stage hookStage, patcher *appsecExprPatcher) ([]Hook, error) {
	var compiled []Hook

	for _, hook := range hooks {
		if hook.OnSuccess != "" && hook.OnSuccess != "continue" && hook.OnSuccess != "break" {
			return nil, fmt.Errorf("invalid 'on_success' for %s hook : %s", stage, hook.OnSuccess)
		}

		if err := hook.Build(ctx, stage, patcher); err != nil {
			return nil, fmt.Errorf("unable to build %s hook : %w", stage, err)
		}

		compiled = append(compiled, hook)
	}

	return compiled, nil
}

// buildPhaseHooks compiles pre_eval / post_eval / on_match hook lists into a
// PhaseHooks. phaseName is only used to wrap errors ("" for the shared section).
func buildPhaseHooks(ctx context.Context, phaseName string, pre, post, onMatch []Hook, patcher *appsecExprPatcher) (PhaseHooks, error) {
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

	if out.PreEval, err = buildHookList(ctx, pre, hookPreEval, patcher); err != nil {
		return PhaseHooks{}, wrap(err)
	}

	if out.PostEval, err = buildHookList(ctx, post, hookPostEval, patcher); err != nil {
		return PhaseHooks{}, wrap(err)
	}

	if out.OnMatch, err = buildHookList(ctx, onMatch, hookOnMatch, patcher); err != nil {
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

func (wc *AppsecConfig) Build(ctx context.Context, hub *cwhub.Hub) (*AppsecRuntimeConfig, error) {
	ret := &AppsecRuntimeConfig{Logger: wc.Logger.WithField("component", "appsec_runtime_config")}

	ret.RequestValidator = apivalidation.NewRequestValidator(wc.Logger.WithField("component", "api_validator"))

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
		wc.Logger.Warningf("default '%s' remediation of %s is none of [%s,%s,%s,%s] ensure bouncer compatibility!",
			wc.DefaultRemediation, wc.Name, BanRemediation, CaptchaRemediation, AllowRemediation, ChallengeRemediation)
	}

	ret.Name = wc.Name
	ret.Config = wc
	ret.DefaultRemediation = wc.DefaultRemediation
	ret.BodySettings = BodySettings{
		MaxSize: DefaultMaxBodySize,
		Action:  BodySizeActionDrop,
	}

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

	if ret.CompiledOnLoad, err = buildHookList(ctx, wc.OnLoad, hookOnLoad, nil); err != nil {
		return nil, err
	}

	if ret.CommonHooks, err = buildPhaseHooks(ctx, "", wc.PreEval, wc.PostEval, wc.OnMatch, patcher); err != nil {
		return nil, err
	}

	if wc.InBand != nil {
		if ret.InBandHooks, err = buildPhaseHooks(ctx, "inband",
			wc.InBand.PreEval, wc.InBand.PostEval, wc.InBand.OnMatch, patcher); err != nil {
			return nil, err
		}
	}

	if wc.OutOfBand != nil {
		if ret.OutOfBandHooks, err = buildPhaseHooks(ctx, "outofband",
			wc.OutOfBand.PreEval, wc.OutOfBand.PostEval, wc.OutOfBand.OnMatch, patcher); err != nil {
			return nil, err
		}

		if len(wc.OutOfBand.OnChallenge) > 0 {
			return nil, errors.New("on_challenge hooks are only valid in-band, not under outofband")
		}

		if len(wc.OutOfBand.OnChallengeSubmit) > 0 {
			return nil, errors.New("on_challenge_submit hooks are only valid in-band, not under outofband")
		}
	}

	// on_challenge hooks: merge top-level and inband-scoped (both are in-band only).
	onChallengeHooks := wc.OnChallenge
	if wc.InBand != nil {
		onChallengeHooks = append(onChallengeHooks, wc.InBand.OnChallenge...)
	}

	if ret.CompiledOnChallenge, err = buildHookList(ctx, onChallengeHooks, hookOnChallenge, patcher); err != nil {
		return nil, err
	}

	// Defining any on_challenge hook implies we need the challenge runtime to
	// validate cookies and submissions, even if the hook bodies never call
	// SendChallenge() themselves.
	if len(ret.CompiledOnChallenge) > 0 {
		patcher.NeedWASMVM = true
	}

	// on_challenge_submit hooks: same merge pattern; in-band only.
	onChallengeSubmitHooks := wc.OnChallengeSubmit
	if wc.InBand != nil {
		onChallengeSubmitHooks = append(onChallengeSubmitHooks, wc.InBand.OnChallengeSubmit...)
	}

	if ret.CompiledOnChallengeSubmit, err = buildHookList(ctx, onChallengeSubmitHooks, hookOnChallengeSubmit, patcher); err != nil {
		return nil, err
	}

	if len(ret.CompiledOnChallengeSubmit) > 0 {
		patcher.NeedWASMVM = true
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
//
// state, when non-nil, is consulted between rule iterations: if
// state.HooksHalted is true (set by a terminal expr helper such as
// RejectSubmission or the on_challenge_submit GrantChallengeCookie),
// remaining rules in this phase are skipped. ProcessOnLoadRules and
// the non-submit phases pass nil — they have no terminal actions
// today.
func (w *AppsecRuntimeConfig) processHooks(hooks []Hook, env map[string]interface{}, hookType string, state *AppsecRequestState) error {
	has_match := false

	for _, rule := range hooks {
		if state != nil && state.HooksHalted {
			w.Logger.Debugf("hooks halted by a terminal action; skipping remaining %s rules", hookType)
			break
		}

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
	return w.processHooks(w.CompiledOnLoad, GetOnLoadEnv(w), "on_load", nil)
}

// runPhaseHooks runs the common hooks for the given stage, then dispatches to
// the in-band or out-of-band phase hooks depending on the request band.
func (w *AppsecRuntimeConfig) runPhaseHooks(stage hookStage, env map[string]interface{}, request *ParsedRequest) error {
	label := stage.String()

	if err := w.processHooks(w.CommonHooks.get(stage), env, label, nil); err != nil {
		return err
	}

	switch {
	case request.IsInBand:
		return w.processHooks(w.InBandHooks.get(stage), env, label+"[inband]", nil)
	case request.IsOutBand:
		return w.processHooks(w.OutOfBandHooks.get(stage), env, label+"[outofband]", nil)
	}

	return nil
}

func (w *AppsecRuntimeConfig) ProcessOnMatchRules(state *AppsecRequestState, request *ParsedRequest, evt pipeline.Event) error {
	return w.runPhaseHooks(hookOnMatch, GetOnMatchEnv(w, state, request, evt), request)
}

// ProcessOnChallengeRules is the in-band-only challenge entry point. It
// handles the PoW worker JS path and the challenge submission path internally,
// validates any existing challenge cookie to populate state.Fingerprint, and
// runs the user-defined on_challenge hook expressions ONLY when there is a
// fingerprint to inspect — i.e. on a valid submission or when a valid cookie
// was presented. Requests with no cookie / invalid cookie / invalid submission
// skip user hooks entirely (there's nothing to evaluate).
func (w *AppsecRuntimeConfig) ProcessOnChallengeRules(ctx context.Context, state *AppsecRequestState, request *ParsedRequest) error {
	if w.ChallengeRuntime == nil {
		return nil
	}

	var path string
	if request.HTTPRequest.URL != nil {
		path = request.HTTPRequest.URL.Path
	}

	// Serve the PoW worker JS (static asset). Skip user expressions.
	if path == challenge.ChallengePowWorkerPath {
		return w.setChallengeResponse(state, http.StatusOK, challenge.PowWorkerJS,
			map[string]string{"Content-Type": "application/javascript", "Cache-Control": "public, max-age=3600"}, nil)
	}

	// Challenge submission: validate, give on_challenge_submit hooks a chance
	// to reject the submission, then issue (or deny) the cookie. Per-route
	// on_challenge inspection happens on subsequent cookie-bearing requests.
	if path == challenge.ChallengeSubmitPath && request.HTTPRequest.Method == http.MethodPost {
		w.Logger.Debugf("validating challenge response")
		w.emitChallengeEvent(request, ChallengeEventInfo{Reason: ChallengeReasonSubmitted})

		ck, fpData, provenDifficulty, err := w.ChallengeRuntime.ValidateChallengeResponse(request.HTTPRequest, request.Body)
		if err != nil {
			w.Logger.Errorf("challenge validation failed: %s", err)
			w.emitChallengeEvent(request, ChallengeEventInfo{
				Reason:     ChallengeReasonFailed,
				FailReason: err.Error(),
				FailErr:    err,
			})
			return w.setChallengeResponse(state, http.StatusOK, bodyChallengeFailed,
				map[string]string{"Content-Type": "application/json", "Cache-Control": "no-cache, no-store"}, nil)
		}

		// Populate state.Fingerprint so on_challenge_submit expressions see
		// the freshly-decrypted fingerprint via the env. CookiePowDifficulty
		// records the difficulty just proven so the Solved event and
		// on_challenge_submit expressions see the real value, not 0.
		state.Fingerprint = &fpData
		state.CookiePowDifficulty = provenDifficulty

		if err := w.processHooks(w.CompiledOnChallengeSubmit, GetOnChallengeSubmitEnv(w, state, request), "on_challenge_submit", state); err != nil {
			w.Logger.Errorf("unable to process on_challenge_submit rules: %s", err)
		}

		if state.SubmissionRejection != nil {
			// The expr-side RejectSubmission helper emits the reject log
			// itself (with the operator-chosen verbosity), so we don't
			// re-log here — just serve the rejection envelope.
			w.emitChallengeEvent(request, ChallengeEventInfo{
				Reason:      ChallengeReasonRejected,
				FailReason:  state.SubmissionRejection.Reason,
				Fingerprint: &fpData,
			})
			return w.setChallengeResponse(state, http.StatusOK, bodyChallengeRejected,
				map[string]string{"Content-Type": "application/json", "Cache-Control": "no-cache, no-store"}, nil)
		}

		w.emitChallengeEvent(request, ChallengeEventInfo{
			Reason:      ChallengeReasonSolved,
			Difficulty:  state.CookiePowDifficulty,
			Fingerprint: &fpData,
		})

		return w.setChallengeResponse(state, http.StatusOK, bodyChallengeOK,
			map[string]string{"Content-Type": "application/json", "Cache-Control": "no-cache, no-store"}, ck)
	}

	// Regular request: validate the existing cookie (if any) to populate
	// fingerprint and remember the difficulty the client proved.
	if httpCookie, err := request.HTTPRequest.Cookie(challenge.ChallengeCookieName); err == nil {
		cookieData, validErr := w.ChallengeRuntime.ValidCookie(httpCookie, request.HTTPRequest.UserAgent())
		switch {
		case validErr != nil:
			// Tampered / replayed / past-window cookies show up here. Count
			// them on the rejected counter with kind=cookie so dashboards
			// can separate "active submission was rejected" from "a stale
			// or forged cookie was presented on a regular request".
			metrics.AppsecChallengeRejected.With(prometheus.Labels{
				"source":        request.RemoteAddrNormalized,
				"appsec_engine": request.AppsecEngine,
				"kind":          "cookie",
				"reason":        classifyCookieErr(validErr),
			}).Inc()
		default:
			fp := cookieData.Fingerprint
			fp.Allowlisted = cookieData.Allowlisted
			fp.AllowlistReason = cookieData.AllowlistReason
			state.Fingerprint = &fp
			state.CookiePowDifficulty = cookieData.PowDifficulty
			// An allowlist cookie minted on a prior request must short-circuit
			// SendChallenge on every replay, exactly like a GrantChallengeCookie
			// call within the current request would. Without this, the visitor
			// gets re-challenged on each hop and the cookie achieves nothing.
			msg := "valid challenge cookie"
			if cookieData.Allowlisted {
				state.ChallengeBypassed = true
				msg = "valid allowlist challenge cookie — bypassing challenge"
			}
			fp.LogAccepted(w.Logger, log.DebugLevel, request.ClientIP, request.RemoteAddrNormalized, msg)
		}
	}

	// No fingerprint to inspect — skip user hooks. This avoids nil-deref inside
	// expr filters like `fingerprint.Bot.X` when no cookie was presented.
	if state.Fingerprint == nil {
		return nil
	}

	return w.processHooks(w.CompiledOnChallenge, GetOnChallengeEnv(ctx, w, state, request), "on_challenge", nil)
}

func (w *AppsecRuntimeConfig) ProcessPreEvalRules(ctx context.Context, state *AppsecRequestState, request *ParsedRequest) error {
	return w.runPhaseHooks(hookPreEval, GetPreEvalEnv(ctx, w, state, request), request)
}

func (w *AppsecRuntimeConfig) ProcessPostEvalRules(ctx context.Context, state *AppsecRequestState, request *ParsedRequest) error {
	return w.runPhaseHooks(hookPostEval, GetPostEvalEnv(ctx, w, state, request), request)
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
	if err := w.SetAction(state, ChallengeRemediation); err != nil {
		return err
	}
	if err := w.SetHTTPCode(state, code); err != nil {
		return err
	}
	// Initial response state defaults BouncerHTTPResponseCode to the "passed" code (see InitRequestState);
	// override it here so the bouncer gets the blocked code while the visitor still receives the challenge page.
	state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
	if err := w.SetChallengeBody(state, body); err != nil {
		return err
	}
	for name, value := range headers {
		if err := w.SetChallengeHeader(state, name, value); err != nil {
			return err
		}
	}
	if cookie != nil {
		if err := w.SetChallengeCookie(state, *cookie); err != nil {
			return err
		}
	}
	state.RequireChallenge = true
	return nil
}

// SetChallengeDifficulty sets the default PoW difficulty on the runtime (used from on_load).
func (w *AppsecRuntimeConfig) SetChallengeDifficulty(level string) error {
	if w.ChallengeRuntime == nil {
		return errors.New("challenge runtime not initialized")
	}

	return w.ChallengeRuntime.SetDifficulty(level)
}

// SetChallengeDifficultyPerRequest sets a per-request PoW difficulty override (used from pre_eval/post_eval).
func (*AppsecRuntimeConfig) SetChallengeDifficultyPerRequest(state *AppsecRequestState, level string) error {
	bits, err := challenge.DifficultyFromLevel(level)
	if err != nil {
		return err
	}

	state.ChallengeDifficulty = &bits

	return nil
}

// SetMaxBodySize sets the maximum allowed body size in bytes. Intended for use in on_load hooks.
func (w *AppsecRuntimeConfig) SetMaxBodySize(size int64) error {
	if size <= 0 {
		return errors.New("max_body_size must be a positive integer")
	}

	w.Logger.Debugf("setting max body size to %d bytes", size)
	w.BodySettings.MaxSize = size
	return nil
}

// SendChallenge issues a challenge HTML page for the current request. Cookie
// and submission handling live in ProcessOnChallengeRules; by the time this
// runs, state.Fingerprint has already been populated if a valid cookie was
// presented. If the client already proved a PoW at least as hard as the
// target difficulty for this request, SendChallenge is a no-op. When the
// target difficulty is raised (e.g. on_challenge calls SetChallengeDifficulty
// to punish a suspect fingerprint), the stored difficulty is lower than the
// target and a fresh challenge is issued.
// EvaluateMismatches runs all library-native + custom fingerprint mismatch
// checks, caches the result on state, and emits one structured Debug log
// line + one metric bump per fired signal on the first call of a given
// request. Subsequent calls return the cached pointer so rules can reference
// the report multiple times without redoing the work.
func (w *AppsecRuntimeConfig) EvaluateMismatches(state *AppsecRequestState, request *ParsedRequest) *challenge.MismatchReport {
	if state.LastMismatchReport != nil {
		return state.LastMismatchReport
	}

	country := exprhelpers.IPToCountryString(request.ClientIP)
	report := state.Fingerprint.ComputeMismatchReport(request.HTTPRequest, country)

	state.LastMismatchReport = report

	if !report.Empty() {
		w.emitMismatchObservability(state, request, report)
	}

	return report
}

// emitMismatchObservability logs the report at Debug level and bumps the
// per-reason/severity Prometheus counter. Called exactly once per request
// from EvaluateMismatches (guarded by state.LastMismatchReport being nil
// on entry).
func (w *AppsecRuntimeConfig) emitMismatchObservability(
	state *AppsecRequestState,
	request *ParsedRequest,
	report *challenge.MismatchReport,
) {
	fsid := ""
	if state.Fingerprint != nil {
		fsid = state.Fingerprint.FSID
	}

	if w.Logger != nil {
		w.Logger.WithFields(log.Fields{
			"fsid":    fsid,
			"source":  request.ClientIP,
			"bouncer": request.RemoteAddrNormalized,
			"reasons": report.Reasons(),
			"high":    report.High(),
			"medium":  report.Medium(),
			"low":     report.Low(),
			"count":   report.Count(),
		}).Debug("fingerprint mismatch")
	}

	for _, sig := range report.Signals {
		metrics.AppsecFingerprintMismatch.With(prometheus.Labels{
			"reason":        sig.Reason,
			"severity":      sig.Severity,
			"appsec_engine": request.AppsecEngine,
		}).Inc()
	}
}

func (w *AppsecRuntimeConfig) SendChallenge(ctx context.Context, state *AppsecRequestState, request *ParsedRequest) error {
	if w.ChallengeRuntime == nil {
		return errors.New("challenge runtime not initialized")
	}

	// SendChallenge can only be called from inband.post_eval and inband.on_challenge.
	// as it's the same expr-env, we need to detect here.
	if state.CurrentPhase != PhaseInBand {
		return errors.New("SendChallenge can only be called from an in-band hook (on_challenge or post_eval)")
	}

	// GrantChallengeCookie earlier in the same request already minted an
	// allowlist cookie; refuse to overwrite it with a challenge page.
	if state.ChallengeBypassed {
		w.Logger.Debugf("SendChallenge no-op: allowlist cookie already granted this request")
		return nil
	}

	target := w.ChallengeRuntime.Difficulty()
	if state.ChallengeDifficulty != nil {
		target = *state.ChallengeDifficulty
	}

	if state.Fingerprint != nil && state.CookiePowDifficulty >= target {
		w.Logger.Debugf("client already proved difficulty %d >= target %d, skipping challenge issue",
			state.CookiePowDifficulty, target)
		return nil
	}

	w.Logger.Debugf("sending challenge at difficulty %d (client proved %d)", target, state.CookiePowDifficulty)

	challengePage, err := w.ChallengeRuntime.GetChallengePage(ctx, request.HTTPRequest.UserAgent(), target)
	if err != nil {
		return fmt.Errorf("unable to get challenge page: %w", err)
	}

	if err := w.setChallengeResponse(state, http.StatusOK, challengePage, map[string]string{"Content-Type": "text/html", "Cache-Control": "no-cache, no-store"}, nil); err != nil {
		return err
	}

	w.emitChallengeEvent(request, ChallengeEventInfo{
		Reason:      ChallengeReasonRequested,
		Difficulty:  target,
		Fingerprint: state.Fingerprint,
	})

	return nil
}

// RejectSubmission flags the in-flight challenge submission so the
// ProcessOnChallengeRules submit-path branch refuses to issue a cookie and
// returns bodyChallengeRejected. Exposed ONLY in the on_challenge_submit
// hook env — calling it from any other phase is a no-op (the field is
// inspected only at submit time).
//
// The reason string is logged server-side and NOT echoed to the client.
func (*AppsecRuntimeConfig) RejectSubmission(state *AppsecRequestState, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "submission rejected by on_challenge_submit"
	}
	state.SubmissionRejection = &SubmissionRejectInfo{Reason: reason}
	return nil
}

// mintAllowlistCookie seals a v0 allowlist cookie, stamps a synthetic
// Allowlisted fingerprint, and flips state.ChallengeBypassed so any later
// SendChallenge in the same request is a no-op. The caller decides how the
// cookie reaches the visitor (redirect vs. inline envelope).
//
// It DELIBERATELY overwrites any prior state.Fingerprint from a real
// submission: an operator allowlist wins. ttlOverride (non-nil) overrides the
// runtime cookie_ttl. Returns ErrAllowlistReasonSize if reason is too long.
func (w *AppsecRuntimeConfig) mintAllowlistCookie(state *AppsecRequestState, request *ParsedRequest, reason string, ttlOverride *time.Duration) (*cookie.AppsecCookie, error) {
	if w.ChallengeRuntime == nil {
		return nil, errors.New("challenge runtime not initialized")
	}

	ck, err := w.ChallengeRuntime.SealAllowlistCookie(request.HTTPRequest, reason, ttlOverride)
	if err != nil {
		return nil, fmt.Errorf("unable to seal allowlist cookie: %w", err)
	}

	state.Fingerprint = &challenge.FingerprintData{
		Allowlisted:     true,
		AllowlistReason: reason,
	}
	state.ChallengeBypassed = true

	// One increment here covers both GrantChallengeCookie (307 redirect from
	// pre_eval/post_eval) and GrantAllowlistCookieInline (inline on the
	// challenge-submit response). Both delegate to this function.
	metrics.AppsecChallengeAccepted.With(prometheus.Labels{
		"source":        request.RemoteAddrNormalized,
		"appsec_engine": request.AppsecEngine,
		"kind":          "granted",
		"reason":        reason, // operator-supplied string passed to GrantChallengeCookie
	}).Inc()

	return ck, nil
}

// GrantChallengeCookie mints an allowlist-bypass cookie and issues an HTTP 307
// redirect carrying it back to the visitor. Used from pre_eval/post_eval.
//
// Why a 307 and not a silent allow: the bouncer only serializes cookies on a
// ChallengeRemediation response (see GenerateResponse), so a plain allow drops
// the Set-Cookie. The redirect to the same URL preserves method+body and
// bounces the visitor back through the WAF with the cookie present, so
// ProcessOnChallengeRules' allowlist branch lets them through on the next hop.
//
// Precedence: see mintAllowlistCookie (operator allowlist overwrites a real
// fingerprint). ttlOverride overrides cookie_ttl. Returns ErrAllowlistReasonSize
// if reason is too long.
func (w *AppsecRuntimeConfig) GrantChallengeCookie(state *AppsecRequestState, request *ParsedRequest, reason string, ttlOverride *time.Duration) error {
	ck, err := w.mintAllowlistCookie(state, request, reason, ttlOverride)
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Location":      request.HTTPRequest.URL.RequestURI(),
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "no-store",
	}

	state.Fingerprint.LogAccepted(
		w.Logger.WithField("location", headers["Location"]),
		log.InfoLevel,
		request.ClientIP,
		request.RemoteAddrNormalized,
		"granted allowlist challenge cookie via 307 redirect",
	)

	return w.setChallengeResponse(state, http.StatusTemporaryRedirect, challenge.GrantRedirectBody, headers, ck)
}

// GrantAllowlistCookieInline mints an allowlist-bypass cookie and attaches it
// to the in-flight challenge-submit envelope. Used from on_challenge_submit,
// where the client awaits the submit JSON envelope and a redirect would break
// its state machine (the envelope is already a ChallengeRemediation, so
// UserCookies is serialized). Same precedence/ttl/error semantics as
// mintAllowlistCookie.
func (w *AppsecRuntimeConfig) GrantAllowlistCookieInline(state *AppsecRequestState, request *ParsedRequest, reason string, ttlOverride *time.Duration) error {
	ck, err := w.mintAllowlistCookie(state, request, reason, ttlOverride)
	if err != nil {
		return err
	}

	if err := w.SetChallengeCookie(state, *ck); err != nil {
		return err
	}

	state.Fingerprint.LogAccepted(w.Logger, log.InfoLevel, request.ClientIP, request.RemoteAddrNormalized, "granted allowlist challenge cookie inline (submit phase)")

	return nil
}

// SetBodySizeExceededAction sets what happens when the body exceeds the maximum size.
// Valid values: "drop" (block request), "partial" (inspect up to max size), "allow" (skip body inspection).
// Intended for use in on_load hooks.
func (w *AppsecRuntimeConfig) SetBodySizeExceededAction(action string) error {
	switch action {
	case BodySizeActionDrop, BodySizeActionPartial, BodySizeActionAllow:
		w.Logger.Debugf("setting body size exceeded action to %q", action)
		w.BodySettings.Action = action

		return nil
	default:
		return fmt.Errorf("invalid body_size_exceeded_action %q (must be %s, %s, or %s)", action, BodySizeActionDrop, BodySizeActionPartial, BodySizeActionAllow)
	}
}

// DisableBodyInspection prevents Coraza from processing the request body for the current request.
// Intended for use in pre_eval hooks.
func (w *AppsecRuntimeConfig) DisableBodyInspection(state *AppsecRequestState) error {
	state.DisableBodyInspection = true
	w.Logger.Debugf("body inspection disabled for this request")

	return nil
}

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
		if resp.UserHeaders == nil {
			// default_remediation: challenge reaches here without any headers set
			// (the internal challenge-serving paths always set Content-Type).
			resp.UserHeaders = make(map[string][]string)
		}
		// If there's no Content-Security-Policy header, add a default one to make sure that the JS code can be evaluated
		if _, ok := resp.UserHeaders["Content-Security-Policy"]; !ok {
			resp.UserHeaders["Content-Security-Policy"] = []string{challenge.DefaultChallengeCSP}
		}
		// Challenge shares the ban/captcha status-code logic below.
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

const schemasSubDir = "schemas"

func (w *AppsecRuntimeConfig) loadAPISchema(ref, filename string, opts *apivalidation.SchemaOptions) error {
	if !filepath.IsLocal(filename) {
		return fmt.Errorf("schema filename %q must be relative to %s and stay within it", filename, schemasSubDir)
	}
	schemaPath := filepath.Join(w.DataDir, schemasSubDir, filename)
	w.Logger.Debugf("loading schema %s for ref %s", schemaPath, ref)
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("unable to read schema file %s : %w", schemaPath, err)
	}
	return w.RequestValidator.LoadSchema(ref, string(schema), opts)
}

func (w *AppsecRuntimeConfig) LoadAPISchemaWithName(ref string, filename string) error {
	return w.loadAPISchema(ref, filename, nil)
}

// LoadAPISchemaWithOptions behaves like LoadAPISchemaWithName but accepts a
// map of policy overrides. Supported keys:
//   - "on_route_not_found":             "drop" | "ignore"  (default: "drop")
//   - "on_method_not_allowed":          "drop" | "ignore"  (default: "drop")
//   - "on_unsupported_security_scheme": "drop" | "ignore"  (default: "drop")
func (w *AppsecRuntimeConfig) LoadAPISchemaWithOptions(ref string, filename string, opts map[string]any) error {
	schemaOpts, err := parseSchemaOptions(opts)
	if err != nil {
		return err
	}
	return w.loadAPISchema(ref, filename, schemaOpts)
}

// RegisterAPISchemaBodyDecoder allows a user's on_load hook to add a Content-Type
// to the set the API schema validator can decode. decoderName must be one of
// the stable built-in identifiers exported by the api_validation package
// ("json", "urlencoded", "multipart", "yaml", "csv", "plain", "file"). Note
// that the underlying kin-openapi decoder registry is process-global: today
// all appsec datasources in the same process share the same set of
// registered body decoders.
func (w *AppsecRuntimeConfig) RegisterAPISchemaBodyDecoder(contentType, decoderName string) error {
	return w.RequestValidator.RegisterBodyDecoder(contentType, decoderName)
}

func parseSchemaOptions(opts map[string]any) (*apivalidation.SchemaOptions, error) {
	out := &apivalidation.SchemaOptions{}
	for k, v := range opts {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("schema option %q must be a string, got %T", k, v)
		}
		switch k {
		case "on_route_not_found":
			out.OnRouteNotFound = apivalidation.Policy(s)
		case "on_method_not_allowed":
			out.OnMethodNotAllowed = apivalidation.Policy(s)
		case "on_unsupported_security_scheme":
			out.OnUnsupportedSecurityScheme = apivalidation.Policy(s)
		default:
			return nil, fmt.Errorf("unknown schema option %q", k)
		}
	}
	return out, nil
}

// validationErrorVarKeys lists the keys published into state.HookVars by
// ValidateRequestWithSchema. Keeping them centralized makes it easy to reset
// them all at the start of each validation call.
var validationErrorVarKeys = []string{
	"validation_error",
	"validation_error_reason",
	"validation_error_field",
	"validation_error_message",
	"validation_error_value",
	"validation_error_expected",
}

// ValidateRequestWithSchema validates r against the OpenAPI schema registered
// under ref. It returns true when the request is valid, false when it is not
// (or when no schema is registered for ref). On failure, structured error
// details are published into state.HookVars under the "validation_error*" keys
// so that subsequent hook expressions (typically the `apply` block of the same
// hook) can build a drop reason or enrich an event. Each call also increments
// the AppsecValidationOKCounter / AppsecValidationFailedCounter metric.
func (w *AppsecRuntimeConfig) ValidateRequestWithSchema(ctx context.Context, state *AppsecRequestState, request *ParsedRequest, ref string) bool {
	for _, k := range validationErrorVarKeys {
		delete(state.HookVars, k)
	}

	r := request.HTTPRequest.Clone(ctx)
	r.Body = io.NopCloser(bytes.NewReader(request.Body))

	err := w.RequestValidator.ValidateRequest(ctx, ref, r)
	if err == nil {
		metrics.AppsecValidationOKCounter.With(prometheus.Labels{
			"source":        request.RemoteAddrNormalized,
			"appsec_engine": request.AppsecEngine,
			"schema_ref":    ref,
		}).Inc()
		return true
	}

	var valErr *apivalidation.ValidationError
	if !errors.As(err, &valErr) {
		// Non-ValidationError paths cover things like "no schema loaded for
		// ref X". Log loudly and surface a synthetic entry so the hook can
		// still build a message.
		w.Logger.Errorf("request validation failed: %s", err)
		valErr = &apivalidation.ValidationError{
			Reason:  "internal",
			Message: err.Error(),
		}
	}

	state.HookVars["validation_error"] = valErr.Error()
	state.HookVars["validation_error_reason"] = valErr.Reason
	state.HookVars["validation_error_field"] = valErr.Field
	state.HookVars["validation_error_message"] = valErr.Message
	state.HookVars["validation_error_value"] = valErr.Value
	state.HookVars["validation_error_expected"] = valErr.Expected

	metrics.AppsecValidationFailedCounter.With(prometheus.Labels{
		"source":        request.RemoteAddrNormalized,
		"appsec_engine": request.AppsecEngine,
		"schema_ref":    ref,
		"reason":        valErr.Reason,
	}).Inc()

	return false
}
