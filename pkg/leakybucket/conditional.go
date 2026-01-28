package leakybucket

import (
	"fmt"
	"sync"

	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

var (
	conditionalExprCache     = make(map[string]*vm.Program)
	conditionalExprCacheLock sync.Mutex
)

type ConditionalProcessor struct {
	ConditionalFilter        string
	ConditionalFilterRuntime *vm.Program
	DumbProcessor
}

func (p *ConditionalProcessor) OnBucketInit(f *BucketFactory) error {
	var err error
	var compiledExpr *vm.Program

	conditionalExprCacheLock.Lock()
	if compiled, ok := conditionalExprCache[f.ConditionalOverflow]; ok {
		conditionalExprCacheLock.Unlock()
		p.ConditionalFilterRuntime = compiled
	} else {
		conditionalExprCacheLock.Unlock()
		// release the lock during compile
		compiledExpr, err = compile(f.ConditionalOverflow, map[string]any{"queue": &pipeline.Queue{}, "leaky": &Leaky{}})
		if err != nil {
			return fmt.Errorf("conditional compile error : %w", err)
		}

		p.ConditionalFilterRuntime = compiledExpr
		conditionalExprCacheLock.Lock()
		conditionalExprCache[f.ConditionalOverflow] = compiledExpr
		conditionalExprCacheLock.Unlock()
	}

	return err
}

func (p *ConditionalProcessor) AfterBucketPour(f *BucketFactory, msg pipeline.Event, l *Leaky) *pipeline.Event {
	var condition, ok bool

	if p.ConditionalFilterRuntime != nil {
		l.logger.Debugf("Running condition expression : %s", p.ConditionalFilter)

		ret, err := exprhelpers.Run(p.ConditionalFilterRuntime,
			map[string]any{"evt": &msg, "queue": l.Queue, "leaky": l},
			l.logger, f.Debug)
		if err != nil {
			l.logger.Errorf("unable to run conditional filter : %s", err)
			return &msg
		}

		l.logger.Debugf("Conditional bucket expression returned : %v", ret)

		if condition, ok = ret.(bool); !ok {
			l.logger.Warningf("overflow condition, unexpected non-bool return : %T", ret)
			return &msg
		}

		if condition {
			l.logger.Debugf("Conditional bucket overflow")
			l.Ovflw_ts = l.Last_ts
			l.Out <- l.Queue
			return nil
		}
	}

	return &msg
}
