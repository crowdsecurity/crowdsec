package appsec

import (
	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge"
	"github.com/crowdsecurity/crowdsec/pkg/appsec/cookie"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

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
