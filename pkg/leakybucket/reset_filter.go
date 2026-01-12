package leakybucket

import (
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
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

var (
	cancelExprCacheLock sync.Mutex
	cancelExprCache     map[string]struct {
		CancelOnFilter *vm.Program
	}
)

func (u *CancelOnFilter) OnBucketPour(_ *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event {
	var condition, ok bool
	if u.CancelOnFilter != nil {
		leaky.logger.Tracef("running cancel_on filter")
		output, err := exprhelpers.Run(u.CancelOnFilter, map[string]any{"evt": &msg}, leaky.logger, u.Debug)
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
			return nil // counter intuitively, we need to keep the message so that it doesn't trigger an endless loop
		}
		leaky.logger.Debugf("reset_filter didn't match")
	}
	return &msg
}

func (*CancelOnFilter) OnBucketOverflow(_ *BucketFactory, _ *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return alert, queue
}

func (*CancelOnFilter) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
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
	}

	cancelExprCacheLock.Unlock()
	// release the lock during compile

	compiledExpr.CancelOnFilter, err = expr.Compile(bucketFactory.CancelOnFilter, exprhelpers.GetExprOptions(map[string]any{"evt": &pipeline.Event{}})...)
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
	return nil
}
