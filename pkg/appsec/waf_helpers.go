package appsec

import (
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
		"SetChallengeCookie":      func(cookie AppsecCookie) error { return w.SetChallengeCookie(state, cookie) },
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
		"AppsecCookie": func(name string) *AppsecCookie {
			return NewAppsecCookie(name)
		},
		"RequireValidChallenge": func( /* TODO: add placeholder configuration for the challenge (for now, it will likely not support anything, but difficulty might be added later)*/ ) error {
			return w.RequireValidChallenge(state, request)
		},
	}
}

func GetPostEvalEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
		"req":         request.HTTPRequest,
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
		"SetChallengeCookie": func(cookie AppsecCookie) error { return w.SetChallengeCookie(state, cookie) },
		"AppsecCookie":       func(name string) *AppsecCookie { return NewAppsecCookie(name) },
	}
}
