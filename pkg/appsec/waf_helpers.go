package appsec

import (
	"github.com/crowdsecurity/crowdsec/pkg/types"
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

func GetPreEvalEnv(w *AppsecRuntimeConfig, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
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
	}
}

func GetPostEvalEnv(w *AppsecRuntimeConfig, request *ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"IsInBand":    request.IsInBand,
		"IsOutBand":   request.IsOutBand,
		"DumpRequest": request.DumpRequest,
	}
}

func GetOnMatchEnv(w *AppsecRuntimeConfig, request *ParsedRequest, evt types.Event) map[string]interface{} {
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
