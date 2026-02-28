package appsec

import (
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

type ExtendedTransaction struct {
	Tx experimental.FullTransaction
}

type interrupter interface {
	Interrupt(interruption *types.Interruption)
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

func (t *ExtendedTransaction) RemoveRuleByTagWithError(tag string) error {
	t.Tx.RemoveRuleByTag(tag)
	return nil
}

func (t *ExtendedTransaction) IsRuleEngineOff() bool {
	return t.Tx.IsRuleEngineOff()
}

func (t *ExtendedTransaction) ProcessLogging() {
	t.Tx.ProcessLogging()
}

func (t *ExtendedTransaction) ProcessConnection(client string, cPort int, server string, sPort int) {
	t.Tx.ProcessConnection(client, cPort, server, sPort)
}

func (t *ExtendedTransaction) AddGetRequestArgument(name string, value string) {
	t.Tx.AddGetRequestArgument(name, value)
}

func (t *ExtendedTransaction) ProcessURI(uri string, method string, httpVersion string) {
	t.Tx.ProcessURI(uri, method, httpVersion)
}

func (t *ExtendedTransaction) AddRequestHeader(name string, value string) {
	t.Tx.AddRequestHeader(name, value)
}

func (t *ExtendedTransaction) SetServerName(name string) {
	t.Tx.SetServerName(name)
}

func (t *ExtendedTransaction) ProcessRequestHeaders() *types.Interruption {
	return t.Tx.ProcessRequestHeaders()
}

func (t *ExtendedTransaction) ProcessRequestBody() (*types.Interruption, error) {
	return t.Tx.ProcessRequestBody()
}

func (t *ExtendedTransaction) WriteRequestBody(body []byte) (*types.Interruption, int, error) {
	return t.Tx.WriteRequestBody(body)
}

// ReadRequestBodyFrom streams the request body from the provided reader into the transaction.
func (t *ExtendedTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	return t.Tx.ReadRequestBodyFrom(r)
}

func (t *ExtendedTransaction) Interruption() *types.Interruption {
	return t.Tx.Interruption()
}

func (t *ExtendedTransaction) IsInterrupted() bool {
	return t.Tx.IsInterrupted()
}

func (t *ExtendedTransaction) Variables() plugintypes.TransactionVariables {
	return t.Tx.Variables()
}

func (t *ExtendedTransaction) MatchedRules() []types.MatchedRule {
	return t.Tx.MatchedRules()
}

func (t *ExtendedTransaction) ID() string {
	return t.Tx.ID()
}

func (t *ExtendedTransaction) Close() error {
	return t.Tx.Close()
}

// IsRequestBodyAccessible exposes whether the engine has request body access enabled.
func (t *ExtendedTransaction) IsRequestBodyAccessible() bool {
	return t.Tx.IsRequestBodyAccessible()
}

func (t *ExtendedTransaction) Interrupt(interruption *types.Interruption) {
	if t == nil || t.Tx == nil || interruption == nil {
		return
	}

	if setter, ok := t.Tx.(interrupter); ok {
		setter.Interrupt(interruption)
	}
}
