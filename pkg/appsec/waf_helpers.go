package appsec

import (
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// parseChallengeCookieTTLArg interprets the optional TTL argument to the
// GrantChallengeCookie expr helper. Zero variadic args means "use the
// runtime default" and yields a nil override. A single non-empty string is
// parsed with time.ParseDuration (e.g. "1h", "30m"). More than one TTL
// argument or an unparseable value is reported as an error so hook authors
// get a precise diagnostic at evaluation time rather than a silent fallback.
func parseChallengeCookieTTLArg(ttl []string) (*time.Duration, error) {
	if len(ttl) == 0 {
		return nil, nil
	}
	if len(ttl) > 1 {
		return nil, fmt.Errorf("GrantChallengeCookie accepts at most one TTL argument, got %d", len(ttl))
	}
	if ttl[0] == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(ttl[0])
	if err != nil {
		return nil, fmt.Errorf("invalid GrantChallengeCookie TTL %q: %w", ttl[0], err)
	}
	if d <= 0 {
		return nil, fmt.Errorf("GrantChallengeCookie TTL must be positive, got %s", d)
	}
	return &d, nil
}

func GetOnLoadEnv(w *AppsecRuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"RemoveInBandRuleByID":    w.DisableInBandRuleByID,
		"RemoveInBandRuleByTag":   w.DisableInBandRuleByTag,
		"RemoveInBandRuleByName":  w.DisableInBandRuleByName,
		"RemoveOutBandRuleByID":   w.DisableOutBandRuleByID,
		"RemoveOutBandRuleByTag":  w.DisableOutBandRuleByTag,
		"RemoveOutBandRuleByName": w.DisableOutBandRuleByName,
		"SetRemediationByTag":     w.SetActionByTag,
		"SetRemediationByID":      w.SetActionByID,
		"SetRemediationByName":    w.SetActionByName,
		"SetChallengeDifficulty":  w.SetChallengeDifficulty,
	}
}

func GetPreEvalEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":                request.IsInBand,
		"IsOutBand":               request.IsOutBand,
		"req":                     request.HTTPRequest,
		"RemoveInBandRuleByID":    func(id int) error { return w.RemoveInbandRuleByID(state, id) },
		"RemoveInBandRuleByName":  func(name string) error { return w.RemoveInbandRuleByName(state, name) },
		"RemoveInBandRuleByTag":   func(tag string) error { return w.RemoveInbandRuleByTag(state, tag) },
		"RemoveOutBandRuleByID":   func(id int) error { return w.RemoveOutbandRuleByID(state, id) },
		"RemoveOutBandRuleByTag":  func(tag string) error { return w.RemoveOutbandRuleByTag(state, tag) },
		"RemoveOutBandRuleByName": func(name string) error { return w.RemoveOutbandRuleByName(state, name) },
		"DropRequest":             func(reason string) error { return w.DropRequest(state, request, reason) },
		"SetChallengeBody":        func(body string) error { return w.SetChallengeBody(state, body) },
		"SetChallengeCookie":      func(cookie cookie.AppsecCookie) error { return w.SetChallengeCookie(state, cookie) },
		"SetRemediationByTag":     w.SetActionByTag,
		"SetRemediationByID":      w.SetActionByID,
		"SetRemediationByName":    w.SetActionByName,
		"SetRemediation": func(action string) error {
			state.PendingAction = &action
			return nil
		},
		"SetReturnCode": func(code int) error {
			state.PendingHTTPCode = &code
			return nil
		},
		"AppsecCookie": func(name string) *cookie.AppsecCookie {
			return cookie.NewAppsecCookie(name)
		},
		"SendChallenge": func() error {
			return w.SendChallenge(state, request)
		},
		"SetChallengeDifficulty": func(level string) error {
			return w.SetChallengeDifficultyPerRequest(state, level)
		},
		"GrantChallengeCookie": func(reason string, ttl ...string) error {
			ttlOverride, err := parseChallengeCookieTTLArg(ttl)
			if err != nil {
				return err
			}
			return w.GrantChallengeCookie(state, request, reason, ttlOverride)
		},
		/*"ValidateChallenge": func(conditions ...bool) (*challenge.ChallengeMatcher, error) {
			return w.ValidateChallenge(state, request, conditions...)
		},*/
		"fingerprint": state.Fingerprint,
	}
}

func GetPostEvalEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
		"req":         request.HTTPRequest,
		"SendChallenge": func() error {
			return w.SendChallenge(state, request)
		},
		"SetChallengeDifficulty": func(level string) error {
			return w.SetChallengeDifficultyPerRequest(state, level)
		},
		"GrantChallengeCookie": func(reason string, ttl ...string) error {
			ttlOverride, err := parseChallengeCookieTTLArg(ttl)
			if err != nil {
				return err
			}
			return w.GrantChallengeCookie(state, request, reason, ttlOverride)
		},
		"fingerprint": state.Fingerprint,
		/*"ValidateChallenge": func(name string, conditions ...bool) (*challenge.ChallengeMatcher, error) {
			return w.ValidateChallenge(state, request, conditions...)
		},*/
	}
}

func GetOnChallengeEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"req":         request.HTTPRequest,
		"IsInBand":    request.IsInBand,
		"fingerprint": state.Fingerprint,
		"SendChallenge": func() error {
			return w.SendChallenge(state, request)
		},
		"SetRemediation": func(action string) error {
			state.PendingAction = &action
			return nil
		},
		"SetReturnCode": func(code int) error {
			state.PendingHTTPCode = &code
			return nil
		},
		"DropRequest": func(reason string) error { return w.DropRequest(state, request, reason) },
		"SetChallengeDifficulty": func(level string) error {
			return w.SetChallengeDifficultyPerRequest(state, level)
		},

		// EvaluateMismatches: aggregate fingerprint mismatch report. First
		// call per request computes the report, caches it on state, and
		// emits one Debug log line + per-signal Prometheus counter bumps;
		// subsequent calls return the cached pointer so rules can chain
		// `.High() >= 1 && .Has("cdp")` without redoing the work.
		//
		// Atomic helpers (fingerprint.UAMobileMismatch,
		// fingerprint.AcceptLanguageMismatch(req),
		// fingerprint.TimezoneCountryMismatch(country)) are methods on
		// `fingerprint` and can still be called directly from rules.
		"EvaluateMismatches": func() *challenge.MismatchReport {
			return w.EvaluateMismatches(state, request)
		},
	}
}

// GetOnChallengeSubmitEnv is the env exposed to on_challenge_submit hooks.
// Deliberately narrow: the hook fires once during the challenge submission
// JSON response, so anything that would change the response shape
// (SendChallenge, SetRemediation, SetReturnCode, SetChallengeDifficulty,
// DropRequest) is intentionally omitted to avoid breaking the client-side
// JS handler. Operators wanting to escalate or block at the next request
// should do so via pre_eval.
func GetOnChallengeSubmitEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"req":         request.HTTPRequest,
		"IsInBand":    request.IsInBand,
		"fingerprint": state.Fingerprint,
		"RejectSubmission": func(reason string) error {
			return w.RejectSubmission(state, reason)
		},
		// In on_challenge_submit the response is the challenge-submit JSON
		// envelope the client is already awaiting; a 307 redirect would
		// break its state machine. Route to the inline variant that
		// attaches the cookie to the existing envelope.
		"GrantChallengeCookie": func(reason string, ttl ...string) error {
			ttlOverride, err := parseChallengeCookieTTLArg(ttl)
			if err != nil {
				return err
			}
			return w.GrantAllowlistCookieInline(state, request, reason, ttlOverride)
		},
		"EvaluateMismatches": func() *challenge.MismatchReport {
			return w.EvaluateMismatches(state, request)
		},
	}
}

func GetOnMatchEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest, evt pipeline.Event) map[string]interface{} {
	return map[string]interface{}{
		"evt":                evt,
		"req":                request.HTTPRequest,
		"IsInBand":           request.IsInBand,
		"IsOutBand":          request.IsOutBand,
		"SetRemediation":     func(action string) error { return w.SetAction(state, action) },
		"SetReturnCode":      func(code int) error { return w.SetHTTPCode(state, code) },
		"CancelEvent":        func() error { return w.CancelEvent(state) },
		"SendEvent":          func() error { return w.SendEvent(state) },
		"CancelAlert":        func() error { return w.CancelAlert(state) },
		"SendAlert":          func() error { return w.SendAlert(state) },
		"DumpRequest":        request.DumpRequest,
		"SetChallengeBody":   func(body string) error { return w.SetChallengeBody(state, body) },
		"SetChallengeCookie": func(cookie cookie.AppsecCookie) error { return w.SetChallengeCookie(state, cookie) },
		"AppsecCookie":       func(name string) *cookie.AppsecCookie { return cookie.NewAppsecCookie(name) },
	}
}
