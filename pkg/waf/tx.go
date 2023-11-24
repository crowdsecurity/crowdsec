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
