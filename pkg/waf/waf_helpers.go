package waf

import (
	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func GetExprWAFOptions(ctx map[string]interface{}) []expr.Option {
	baseHelpers := exprhelpers.GetExprOptions(ctx)

	for _, function := range exprFuncs {
		baseHelpers = append(baseHelpers,
			expr.Function(function.name,
				function.function,
				function.signature...,
			))
	}
	return baseHelpers
}

func GetOnLoadEnv(w *WaapRuntimeConfig) map[string]interface{} {
	//FIXME: use expr.Function instead of this
	return map[string]interface{}{
		"RemoveInBandRuleByID":   w.DisableInBandRuleByID,
		"RemoveOutBandRuleByID":  w.DisableOutBandRuleByID,
		"RemoveInBandRuleByTag":  w.DisableInBandRuleByTag,
		"RemoveOutBandRuleByTag": w.DisableOutBandRuleByTag,
		"SetRemediationByTag":    w.SetActionByTag,
		"SetRemediationByID":     w.SetActionByID,
		"SetRemediationByName":   w.SetActionByName,
	}
}

func GetPreEvalEnv(w *WaapRuntimeConfig, request *ParsedRequest) map[string]interface{} {
	//FIXME: use expr.Function instead of this
	return map[string]interface{}{
		"IsInBand":              request.IsInBand,
		"IsOutBand":             request.IsOutBand,
		"RemoveInBandRuleByID":  w.RemoveInbandRuleByID,
		"RemoveOutBandRuleByID": w.RemoveOutbandRuleByID,
		"SetRemediationByTag":   w.SetActionByTag,
		"SetRemediationByID":    w.SetActionByID,
		"SetRemediationByName":  w.SetActionByName,
	}
}

func GetPostEvalEnv(w *WaapRuntimeConfig, request *ParsedRequest) map[string]interface{} {
	//FIXME: use expr.Function instead of this
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
	}
}

func GetOnMatchEnv(w *WaapRuntimeConfig, request *ParsedRequest, evt types.Event) map[string]interface{} {
	//FIXME: use expr.Function instead of this
	return map[string]interface{}{
		"evt":            evt,
		"req":            request,
		"IsInBand":       request.IsInBand,
		"IsOutBand":      request.IsOutBand,
		"SetRemediation": w.SetAction,
		"SetReturnCode":  w.SetHTTPCode,
		"CancelEvent":    w.CancelEvent,
		"SendEvent":      w.SendEvent,
		"CancelAlert":    w.CancelAlert,
		"SendAlert":      w.SendAlert,
		"DumpRequest":    request.DumpRequest,
	}
}
