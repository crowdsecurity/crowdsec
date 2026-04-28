package appsec

import (
	"context"
	"net/http"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func GetOnLoadEnv(w *AppsecRuntimeConfig) map[string]interface{} {
	return map[string]interface{}{
		"RemoveInBandRuleByID":         w.DisableInBandRuleByID,
		"RemoveInBandRuleByTag":        w.DisableInBandRuleByTag,
		"RemoveInBandRuleByName":       w.DisableInBandRuleByName,
		"RemoveOutBandRuleByID":        w.DisableOutBandRuleByID,
		"RemoveOutBandRuleByTag":       w.DisableOutBandRuleByTag,
		"RemoveOutBandRuleByName":      w.DisableOutBandRuleByName,
		"SetRemediationByTag":          w.SetActionByTag,
		"SetRemediationByID":           w.SetActionByID,
		"SetRemediationByName":         w.SetActionByName,
		"LoadAPISchemaWithName":        w.LoadAPISchemaWithName,
		"LoadAPISchemaWithOptions":     w.LoadAPISchemaWithOptions,
		"RegisterAPISchemaBodyDecoder": w.RegisterAPISchemaBodyDecoder,
		"SetMaxBodySize":               w.SetMaxBodySize,
		"SetBodySizeExceededAction":    w.SetBodySizeExceededAction,
	}
}

func GetPreEvalEnv(ctx context.Context, w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":                request.IsInBand,
		"IsOutBand":               request.IsOutBand,
		"req":                     request.HTTPRequest,
		"hook_vars":               state.HookVars,
		"RemoveInBandRuleByID":    func(id int) error { return w.RemoveInbandRuleByID(state, id) },
		"RemoveInBandRuleByName":  func(name string) error { return w.RemoveInbandRuleByName(state, name) },
		"RemoveInBandRuleByTag":   func(tag string) error { return w.RemoveInbandRuleByTag(state, tag) },
		"RemoveOutBandRuleByID":   func(id int) error { return w.RemoveOutbandRuleByID(state, id) },
		"RemoveOutBandRuleByTag":  func(tag string) error { return w.RemoveOutbandRuleByTag(state, tag) },
		"RemoveOutBandRuleByName": func(name string) error { return w.RemoveOutbandRuleByName(state, name) },
		"DropRequest":             func(reason string) error { return w.DropRequest(state, request, reason) },
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
		"ValidateRequestWithSchema": func(ref string, r *http.Request) bool {
			return w.ValidateRequestWithSchema(ctx, state, request, ref, r)
		},
		"DisableBodyInspection": func() error { return w.DisableBodyInspection(state) },
	}
}

func GetPostEvalEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
		"req":         request.HTTPRequest,
		"hook_vars":   state.HookVars,
	}
}

func GetOnMatchEnv(w *AppsecRuntimeConfig, state *AppsecRequestState, request *ParsedRequest, evt pipeline.Event) map[string]interface{} {
	return map[string]interface{}{
		"evt":            evt,
		"req":            request.HTTPRequest,
		"hook_vars":      state.HookVars,
		"IsInBand":       request.IsInBand,
		"IsOutBand":      request.IsOutBand,
		"SetRemediation": func(action string) error { return w.SetAction(state, action) },
		"SetReturnCode":  func(code int) error { return w.SetHTTPCode(state, code) },
		"CancelEvent":    func() error { return w.CancelEvent(state) },
		"SendEvent":      func() error { return w.SendEvent(state) },
		"CancelAlert":    func() error { return w.CancelAlert(state) },
		"SendAlert":      func() error { return w.SendAlert(state) },
		"DumpRequest":    request.DumpRequest,
	}
}
