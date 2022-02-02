package leakybucket

import (
	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

// ResetFilter allows to kill the bucket (without overflowing), if a particular condition is met.
// An example would be a scenario to detect aggressive crawlers that *do not* fetch any static ressources :
// type : leaky
// filter: filter: "evt.Meta.log_type == 'http_access-log'
// reset_filter: evt.Parsed.request endswith '.css'
// ....
// Thus, if the bucket receives a request that matches fetching a static ressource (here css), it cancels itself

type CancelOnFilter struct {
	CancelOnFilter      *vm.Program
	CancelOnFilterDebug *exprhelpers.ExprDebugger
}

func (u *CancelOnFilter) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		var condition, ok bool
		if u.CancelOnFilter != nil {
			leaky.logger.Tracef("running cancel_on filter")
			output, err := expr.Run(u.CancelOnFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &msg}))
			if err != nil {
				leaky.logger.Warningf("cancel_on error : %s", err)
				return &msg
			}
			//only run debugger expression if condition is false
			if u.CancelOnFilterDebug != nil {
				u.CancelOnFilterDebug.Run(leaky.logger, condition, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &msg}))
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

func (u *CancelOnFilter) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *Queue) (types.RuntimeAlert, *Queue) {
		return alert, queue
	}
}

func (u *CancelOnFilter) OnBucketInit(bucketFactory *BucketFactory) error {
	var err error

	u.CancelOnFilter, err = expr.Compile(bucketFactory.CancelOnFilter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
	if err != nil {
		bucketFactory.logger.Errorf("reset_filter compile error : %s", err)
		return err
	}
	if bucketFactory.Debug {
		u.CancelOnFilterDebug, err = exprhelpers.NewDebugger(bucketFactory.CancelOnFilter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		if err != nil {
			bucketFactory.logger.Errorf("reset_filter debug error : %s", err)
			return err
		}
	}
	return err
}
