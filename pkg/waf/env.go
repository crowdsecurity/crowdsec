package waf

import (
	"github.com/crowdsecurity/coraza/v3"
	"github.com/crowdsecurity/coraza/v3/experimental"
)

type ExtendedTransaction struct {
	Tx experimental.FullTransaction
}

func NewExtendedTransaction(engine coraza.WAF, uuid string) ExtendedTransaction {
	inBoundTx := engine.NewTransactionWithID(uuid)
	expTx := inBoundTx.(experimental.FullTransaction)
	tx := NewTransaction(expTx)
	return tx
}

func NewTransaction(tx experimental.FullTransaction) ExtendedTransaction {
	return ExtendedTransaction{Tx: tx}
}

func (t *ExtendedTransaction) RemoveRuleByIDWithError(id int) error {
	t.Tx.RemoveRuleByID(id)
	return nil
}

// simply used to ease the compilation & runtime of the hooks
func GetHookEnv(w *WaapRuntimeConfig, request ParsedRequest) map[string]interface{} {
	return map[string]interface{}{
		"inband_rules":          w.InBandRules,
		"outband_rules":         w.OutOfBandRules,
		"req":                   request,
		"RemoveInbandRuleByID":  w.RemoveInbandRuleByID,
		"RemoveOutbandRuleByID": w.RemoveOutbandRuleByID,
		"SetAction":             w.SetAction,
		"SetActionByTag":        w.SetActionByTag,
		"SetHTTPCode":           w.SetHTTPCode,
		"SetActionByID":         w.SetActionByID,
		"CancelEvent":           w.CancelEvent,
		"IsInBand":              request.IsInBand,
		"IsOutBand":             request.IsOutBand,
	}
}
