package leakybucket

import (
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Uniq creates three new functions that share the same initialisation and the same scope.
// They are triggered respectively:
// on pour
// on overflow
// on leak

var (
	uniqExprCache     map[string]vm.Program
	uniqExprCacheLock sync.Mutex
)

type Uniq struct {
	DistinctCompiled *vm.Program
	KeyCache         map[string]bool
	CacheMutex       sync.Mutex
}

func (u *Uniq) OnBucketPour(bucketFactory *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event {
	element, err := getElement(msg, u.DistinctCompiled)
	if err != nil {
		leaky.logger.Errorf("Uniq filter exec failed : %v", err)
		return &msg
	}
	leaky.logger.Tracef("Uniq '%s' -> '%s'", bucketFactory.Distinct, element)
	u.CacheMutex.Lock()
	defer u.CacheMutex.Unlock()
	if _, ok := u.KeyCache[element]; !ok {
		leaky.logger.Debugf("Uniq(%s) : ok", element)
		u.KeyCache[element] = true
		return &msg
	}
	leaky.logger.Debugf("Uniq(%s) : ko, discard event", element)
	return nil
}

func (*Uniq) OnBucketOverflow(_ *BucketFactory, _ *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return alert, queue
}

func (*Uniq) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
}

func (u *Uniq) OnBucketInit(bucketFactory *BucketFactory) error {
	if uniqExprCache == nil {
		uniqExprCache = make(map[string]vm.Program)
	}

	uniqExprCacheLock.Lock()
	if compiled, ok := uniqExprCache[bucketFactory.Distinct]; ok {
		uniqExprCacheLock.Unlock()
		u.DistinctCompiled = &compiled
	} else {
		uniqExprCacheLock.Unlock()
		// release the lock during compile
		compiledExpr, err := expr.Compile(bucketFactory.Distinct, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
		if err != nil {
			return err
		}
		u.DistinctCompiled = compiledExpr
		uniqExprCacheLock.Lock()
		uniqExprCache[bucketFactory.Distinct] = *compiledExpr
		uniqExprCacheLock.Unlock()
	}
	u.KeyCache = make(map[string]bool)
	return nil
}

// getElement computes a string from an event and a filter
func getElement(msg pipeline.Event, cFilter *vm.Program) (string, error) {
	el, err := expr.Run(cFilter, map[string]any{"evt": &msg})
	if err != nil {
		return "", err
	}
	element, ok := el.(string)
	if !ok {
		return "", err
	}
	return element, nil
}
