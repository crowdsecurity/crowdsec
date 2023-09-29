package leakybucket

import (
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// ResetFilter allows to kill the bucket (without overflowing), if a particular condition is met.
// An example would be a scenario to detect aggressive crawlers that *do not* fetch any static resources :
// type : leaky
// filter: "evt.Meta.log_type == 'http_access-log'
// reset_filter: evt.Parsed.request endswith '.css'
// ....
// Thus, if the bucket receives a request that matches fetching a static resource (here css), it cancels itself

type CancelOnFilter struct {
	CancelOnFilter *vm.Program
	Debug          bool
}

var cancelExprCacheLock sync.Mutex
var cancelExprCache map[string]struct {
	CancelOnFilter *vm.Program
}

func (u *CancelOnFilter) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		var condition, ok bool
		if u.CancelOnFilter != nil {
			leaky.logger.Tracef("running cancel_on filter")
			output, err := exprhelpers.Run(u.CancelOnFilter, map[string]interface{}{"evt": &msg}, leaky.logger, u.Debug)
			if err != nil {
				leaky.logger.Warningf("cancel_on error : %s", err)
				return &msg
			}
			if condition, ok = output.(bool); !ok {
				leaky.logger.Warningf("cancel_on, unexpected non-bool return : %T", output)
				return &msg
			}
			if condition {
				leaky.logger.Debugf("reset_filter matched, kill bucket")
				leaky.Suicide <- true
				return nil //counter intuitively, we need to keep the message so that it doesn't trigger an endless loop
			}
			leaky.logger.Debugf("reset_filter didn't match")
		}
		return &msg
	}
}

func (u *CancelOnFilter) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *types.Queue) (types.RuntimeAlert, *types.Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *types.Queue) (types.RuntimeAlert, *types.Queue) {
		return alert, queue
	}
}

func (u *CancelOnFilter) AfterBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		return &msg
	}
}

func (u *CancelOnFilter) OnBucketInit(bucketFactory *BucketFactory) error {
	var err error
	var compiledExpr struct {
		CancelOnFilter *vm.Program
	}

	if cancelExprCache == nil {
		cancelExprCache = make(map[string]struct {
			CancelOnFilter *vm.Program
		})
	}

	cancelExprCacheLock.Lock()
	if compiled, ok := cancelExprCache[bucketFactory.CancelOnFilter]; ok {
		cancelExprCacheLock.Unlock()
		u.CancelOnFilter = compiled.CancelOnFilter
		return nil
	} else {
		cancelExprCacheLock.Unlock()
		//release the lock during compile

		compiledExpr.CancelOnFilter, err = expr.Compile(bucketFactory.CancelOnFilter, exprhelpers.GetExprOptions(map[string]interface{}{"evt": &types.Event{}})...)
		if err != nil {
			bucketFactory.logger.Errorf("reset_filter compile error : %s", err)
			return err
		}
		u.CancelOnFilter = compiledExpr.CancelOnFilter
		if bucketFactory.Debug {
			u.Debug = true
		}
		cancelExprCacheLock.Lock()
		cancelExprCache[bucketFactory.CancelOnFilter] = compiledExpr
		cancelExprCacheLock.Unlock()
	}
	return err
}
