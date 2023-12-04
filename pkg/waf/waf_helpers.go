package waf

import (
	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

var exprOnLoadOptions = []expr.Option{}
var exprPreEvalOptions = []expr.Option{}
var exprPostEvalOptions = []expr.Option{}
var exprOnMatchOptions = []expr.Option{}

func GetOnLoadEnv(ctx map[string]interface{}, w *WaapRuntimeConfig) []expr.Option {
	baseHelpers := exprhelpers.GetExprOptions(ctx)
	onLoadHelpers := []exprhelpers.ExprCustomFunc{
		{
			Name:     "RemoveInBandRuleByID",
			Function: w.DisableInBandRuleByID,
			Signature: []interface{}{
				new(func(int) error),
			},
		},
		{
			Name:     "RemoveInBandRuleByTag",
			Function: w.DisableInBandRuleByTag,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveInBandRuleByName",
			Function: w.DisableInBandRuleByName,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByID",
			Function: w.DisableOutBandRuleByID,
			Signature: []interface{}{
				new(func(int) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByTag",
			Function: w.DisableOutBandRuleByTag,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByName",
			Function: w.DisableOutBandRuleByName,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "SetRemediationByTag",
			Function: w.SetActionByTag,
			Signature: []interface{}{
				new(func(string, string) error),
			},
		},
		{
			Name:     "SetRemediationByID",
			Function: w.SetActionByID,
			Signature: []interface{}{
				new(func(int, string) error),
			},
		},
		{
			Name:     "SetRemediationByName",
			Function: w.SetActionByName,
			Signature: []interface{}{
				new(func(string, string) error),
			},
		},
	}

	if len(exprOnLoadOptions) == 0 {
		for _, function := range onLoadHelpers {
			exprOnLoadOptions = append(exprOnLoadOptions,
				expr.Function(
					function.Name,
					function.Function,
					function.Signature...,
				),
			)
		}
		exprOnLoadOptions = append(exprOnLoadOptions, baseHelpers...)
	}

	return exprOnLoadOptions
}

func GetPreEvalEnv(ctx map[string]interface{}, w *WaapRuntimeConfig, request *ParsedRequest) []expr.Option {

	baseHelpers := exprhelpers.GetExprOptions(ctx)
	preEvalHelpers := []exprhelpers.ExprCustomFunc{
		{
			Name:     "RemoveInBandRuleByID",
			Function: w.RemoveInbandRuleByID,
			Signature: []interface{}{
				new(func(int) error),
			},
		},
		{
			Name:     "RemoveInBandRuleByTag",
			Function: w.RemoveInbandRuleByTag,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveInBandRuleByName",
			Function: w.RemoveInbandRuleByName,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByID",
			Function: w.RemoveOutbandRuleByID,
			Signature: []interface{}{
				new(func(int) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByTag",
			Function: w.RemoveOutbandRuleByTag,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "RemoveOutBandRuleByName",
			Function: w.RemoveOutbandRuleByName,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "SetRemediationByTag",
			Function: w.SetActionByTag,
			Signature: []interface{}{
				new(func(string, string) error),
			},
		},
		{
			Name:     "SetRemediationByID",
			Function: w.SetActionByID,
			Signature: []interface{}{
				new(func(int, string) error),
			},
		},
		{
			Name:     "SetRemediationByName",
			Function: w.SetActionByName,
			Signature: []interface{}{
				new(func(string, string) error),
			},
		},
	}

	if len(exprPreEvalOptions) == 0 {
		for _, function := range preEvalHelpers {
			exprPreEvalOptions = append(exprPreEvalOptions,
				expr.Function(
					function.Name,
					function.Function,
					function.Signature...,
				),
			)
		}
		exprPreEvalOptions = append(exprPreEvalOptions, baseHelpers...)
	}

	return exprPreEvalOptions

	//FIXME: use expr.Function instead of this
	/*return map[string]interface{}{
		"IsInBand":                request.IsInBand,
		"IsOutBand":               request.IsOutBand,
		"RemoveInBandRuleByID":    w.RemoveInbandRuleByID,
		"RemoveInBandRuleByName":  w.RemoveInbandRuleByName,
		"RemoveInBandRuleByTag":   w.RemoveInbandRuleByTag,
		"RemoveOutBandRuleByID":   w.RemoveOutbandRuleByID,
		"RemoveOutBandRuleByTag":  w.RemoveOutbandRuleByTag,
		"RemoveOutBandRuleByName": w.RemoveOutbandRuleByName,
		"SetRemediationByTag":     w.SetActionByTag,
		"SetRemediationByID":      w.SetActionByID,
		"SetRemediationByName":    w.SetActionByName,
	}*/
}

func GetPostEvalEnv(ctx map[string]interface{}, w *WaapRuntimeConfig, request *ParsedRequest) []expr.Option {
	baseHelpers := exprhelpers.GetExprOptions(ctx)
	postEvalHelpers := []exprhelpers.ExprCustomFunc{
		{
			Name:     "DumpRequest",
			Function: request.DumpRequest,
			Signature: []interface{}{
				new(func() *ReqDumpFilter),
			},
		},
	}

	if len(exprPostEvalOptions) == 0 {
		for _, function := range postEvalHelpers {
			exprPostEvalOptions = append(exprPostEvalOptions,
				expr.Function(
					function.Name,
					function.Function,
					function.Signature...,
				),
			)
		}
		exprPostEvalOptions = append(exprPostEvalOptions, baseHelpers...)
	}

	return exprPostEvalOptions

	/*//FIXME: use expr.Function instead of this
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
	}*/
}

func GetOnMatchEnv(ctx map[string]interface{}, w *WaapRuntimeConfig, request *ParsedRequest) []expr.Option {
	baseHelpers := exprhelpers.GetExprOptions(ctx)
	onMatchHelpers := []exprhelpers.ExprCustomFunc{
		{
			Name:     "SetRemediation",
			Function: w.SetAction,
			Signature: []interface{}{
				new(func(string) error),
			},
		},
		{
			Name:     "SetReturnCode",
			Function: w.SetHTTPCode,
			Signature: []interface{}{
				new(func(int) error),
			},
		},
		{
			Name:     "CancelEvent",
			Function: w.CancelEvent,
			Signature: []interface{}{
				new(func() error),
			},
		},
		{
			Name:     "SendEvent",
			Function: w.SendEvent,
			Signature: []interface{}{
				new(func() error),
			},
		},
		{
			Name:     "CancelAlert",
			Function: w.CancelAlert,
			Signature: []interface{}{
				new(func() error),
			},
		},
		{
			Name:     "SendAlert",
			Function: w.SendAlert,
			Signature: []interface{}{
				new(func() error),
			},
		},
		{
			Name:     "DumpRequest",
			Function: request.DumpRequest,
			Signature: []interface{}{
				new(func() *ReqDumpFilter),
			},
		},
	}

	if len(exprOnMatchOptions) == 0 {
		for _, function := range onMatchHelpers {
			exprOnMatchOptions = append(exprOnMatchOptions,
				expr.Function(
					function.Name,
					function.Function,
					function.Signature...,
				),
			)
		}
		exprOnMatchOptions = append(exprOnMatchOptions, baseHelpers...)
	}

	return exprOnMatchOptions

	/*//FIXME: use expr.Function instead of this
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
	}*/
}
