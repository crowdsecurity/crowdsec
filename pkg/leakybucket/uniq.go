package leakybucket

import (
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// Uniq creates three new functions that share the same initialisation and the same scope.
// They are triggered respectively:
// on pour
// on overflow
// on leak

var uniqExprCache map[string]vm.Program
var uniqExprCacheLock sync.Mutex

type Uniq struct {
	DistinctCompiled *vm.Program
	KeyCache         map[string]bool
	CacheMutex       sync.Mutex
}

func (u *Uniq) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
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

		} else {
			leaky.logger.Debugf("Uniq(%s) : ko, discard event", element)
			return nil
		}
	}
}

func (u *Uniq) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *types.Queue) (types.RuntimeAlert, *types.Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *types.Queue) (types.RuntimeAlert, *types.Queue) {
		return alert, queue
	}
}

func (u *Uniq) AfterBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}

func (u *Uniq) OnBucketInit(bucketFactory *BucketFactory) error {
	var err error
	var compiledExpr *vm.Program

	if uniqExprCache == nil {
		uniqExprCache = make(map[string]vm.Program)
	}

	uniqExprCacheLock.Lock()
	if compiled, ok := uniqExprCache[bucketFactory.Distinct]; ok {
		uniqExprCacheLock.Unlock()
		u.DistinctCompiled = &compiled
	} else {
		uniqExprCacheLock.Unlock()
		//release the lock during compile
		compiledExpr, err = expr.Compile(bucketFactory.Distinct, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		u.DistinctCompiled = compiledExpr
		uniqExprCacheLock.Lock()
		uniqExprCache[bucketFactory.Distinct] = *compiledExpr
		uniqExprCacheLock.Unlock()
	}
	u.KeyCache = make(map[string]bool)
	return err
}

// getElement computes a string from an event and a filter
func getElement(msg types.Event, cFilter *vm.Program) (string, error) {
	el, err := expr.Run(cFilter, map[string]interface{}{"evt": &msg})
	if err != nil {
		return "", err
	}
	element, ok := el.(string)
	if !ok {
		return "", err
	}
	return element, nil
}
