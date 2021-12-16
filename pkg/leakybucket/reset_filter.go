package leakybucket

import (
	"time"

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

type ResetFilter struct {
	ResetFilter          *vm.Program
	ResetFilterSafeGuard map[string]time.Time
}

func (u *ResetFilter) OnBucketPour(bucketFactory *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, leaky *Leaky) *types.Event {
		var condition, ok bool
		if u.ResetFilter != nil {
			leaky.logger.Tracef("running cancel_on filter")
			output, err := expr.Run(u.ResetFilter, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &msg}))
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
			} else {
				leaky.logger.Debugf("reset_filter didn't match")
			}
		}
		return &msg
	}
}

func (u *ResetFilter) OnBucketOverflow(bucketFactory *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue) {
	return func(leaky *Leaky, alert types.RuntimeAlert, queue *Queue) (types.RuntimeAlert, *Queue) {
		return alert, queue
	}
}

func (u *ResetFilter) OnBucketInit(bucketFactory *BucketFactory) error {
	var err error

	u.ResetFilter, err = expr.Compile(bucketFactory.ResetFilter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
	if err != nil {
		bucketFactory.logger.Debugf("reset_filter compile error : %s", err)
	}
	return err
}
