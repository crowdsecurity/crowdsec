package waf

import "github.com/crowdsecurity/coraza/v3/experimental"

type Transaction struct {
	Tx experimental.FullTransaction
}

func NewTransaction(tx experimental.FullTransaction) Transaction {
	return Transaction{Tx: tx}
}

func (t *Transaction) RemoveRuleByIDWithError(id int) error {
	t.Tx.RemoveRuleByID(id)
	return nil
}

func GetEnv() map[string]interface{} {
	ResponseRequest := ResponseRequest{}
	ParsedRequest := ParsedRequest{}
	Rules := &WafRulesCollection{}
	Tx := Transaction{}

	return map[string]interface{}{
		"rules":              Rules,
		"req":                ParsedRequest,
		"SetRemediation":     ResponseRequest.SetRemediation,
		"SetRemediationByID": ResponseRequest.SetRemediationByID,
		"CancelEvent":        ResponseRequest.CancelEvent,
		"RemoveRuleByID":     Tx.RemoveRuleByIDWithError,
	}
}
