package leakybucket

import (
	"sync"

	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// CancelOnFilter allows to kill the bucket (without overflowing), if a particular condition is met.
// An example would be a scenario to detect aggressive crawlers that *do not* fetch any static resources :
// type : leaky
// filter: "evt.Meta.log_type == 'http_access-log'
// reset_filter: evt.Parsed.request endswith '.css'
// ....
// Thus, if the bucket receives a request that matches fetching a static resource (here css), it cancels itself

type CancelProcessor struct {
	CancelOnFilter *vm.Program
	Debug          bool
}

var (
	cancelExprCacheLock sync.Mutex
	cancelExprCache     map[string]struct {
		CancelOnFilter *vm.Program
	}
)

func (p *CancelProcessor) OnBucketPour(_ *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event {
	var condition, ok bool
	if p.CancelOnFilter != nil {
		leaky.logger.Tracef("running cancel_on filter")
		output, err := exprhelpers.Run(p.CancelOnFilter, map[string]any{"evt": &msg}, leaky.logger, p.Debug)
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

func (*CancelProcessor) OnBucketOverflow(_ *BucketFactory, _ *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return alert, queue
}

func (*CancelProcessor) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
}

func (p *CancelProcessor) OnBucketInit(f *BucketFactory) error {
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
	if compiled, ok := cancelExprCache[f.Spec.CancelOnFilter]; ok {
		cancelExprCacheLock.Unlock()
		p.CancelOnFilter = compiled.CancelOnFilter
		return nil
	}

	cancelExprCacheLock.Unlock()
	// release the lock during compile

	compiledExpr.CancelOnFilter, err = compile(f.Spec.CancelOnFilter, nil)
	if err != nil {
		f.logger.Errorf("reset_filter compile error : %s", err)
		return err
	}
	p.CancelOnFilter = compiledExpr.CancelOnFilter
	if f.Spec.Debug {
		p.Debug = true
	}
	cancelExprCacheLock.Lock()
	cancelExprCache[f.Spec.CancelOnFilter] = compiledExpr
	cancelExprCacheLock.Unlock()
	return nil
}
