package waf

import (
	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

var exprFunctionOptions []expr.Option

func initWafHelpers() {
	exprFunctionOptions = []expr.Option{}
	for _, function := range exprFuncs {
		exprFunctionOptions = append(exprFunctionOptions,
			expr.Function(function.name,
				function.function,
				function.signature...,
			))
	}
}

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
	}
}

func GetOnMatchEnv(w *WaapRuntimeConfig, request *ParsedRequest) map[string]interface{} {
	//FIXME: use expr.Function instead of this
	return map[string]interface{}{
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
