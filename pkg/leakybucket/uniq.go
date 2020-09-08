package leakybucket

import (
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

type Uniq struct {
	DistinctCompiled *vm.Program
}

func (u *Uniq) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		element, err := getElement(msg, u.DistinctCompiled)
		if err != nil {
			leaky.logger.Errorf("Uniq filter exec failed : %v", err)
			return &msg
		}
		leaky.logger.Tracef("Uniq '%s' -> '%s'", bucketFactory.Distinct, element)
		for _, evt := range leaky.Queue.GetQueue() {
			if val, err := getElement(evt, u.DistinctCompiled); err == nil && val == element {
				leaky.logger.Debugf("Uniq(%s) : ko, discard event", element)
				return nil
			}
			if err != nil {
				leaky.logger.Errorf("Uniq filter exec failed : %v", err)
			}
		}
		leaky.logger.Debugf("Uniq(%s) : ok", element)
		return &msg
	}
}

func (u *Uniq) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.Alert, *Queue) (types.Alert, *Queue) {
	return func(leaky *Leaky, alert types.Alert, queue *Queue) (types.Alert, *Queue) {
		return alert, queue
	}
}

func (u *Uniq) OnBucketInit(bucketFactory *BucketFactory) error {
	var err error

	u.DistinctCompiled, err = expr.Compile(bucketFactory.Distinct, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
	return err
}

// getElement computes a string from an event and a filter
func getElement(msg types.Event, cFilter *vm.Program) (string, error) {
	el, err := expr.Run(cFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &msg}))
	if err != nil {
		return "", err
	}
	element, ok := el.(string)
	if !ok {
		return "", err
	}
	return element, nil
}
