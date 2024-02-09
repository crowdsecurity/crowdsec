package leakybucket

import (
	"fmt"
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

var conditionalExprCache map[string]vm.Program
var conditionalExprCacheLock sync.Mutex

type ConditionalOverflow struct {
	ConditionalFilter        string
	ConditionalFilterRuntime *vm.Program
	DumbProcessor
}

func (c *ConditionalOverflow) OnBucketInit(g *BucketFactory) error {
	var err error
	var compiledExpr *vm.Program

	if conditionalExprCache == nil {
		conditionalExprCache = make(map[string]vm.Program)
	}
	conditionalExprCacheLock.Lock()
	if compiled, ok := conditionalExprCache[g.ConditionalOverflow]; ok {
		conditionalExprCacheLock.Unlock()
		c.ConditionalFilterRuntime = &compiled
	} else {
		conditionalExprCacheLock.Unlock()
		//release the lock during compile
		compiledExpr, err = expr.Compile(g.ConditionalOverflow, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &types.Queue{}, "leaky": &Leaky{}, "evt": &types.Event{}})...)
		if err != nil {
			return fmt.Errorf("conditional compile error : %w", err)
		}
		c.ConditionalFilterRuntime = compiledExpr
		conditionalExprCacheLock.Lock()
		conditionalExprCache[g.ConditionalOverflow] = *compiledExpr
		conditionalExprCacheLock.Unlock()
	}
	return err
}

func (c *ConditionalOverflow) AfterBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {
		var condition, ok bool
		if c.ConditionalFilterRuntime != nil {
			l.logger.Debugf("Running condition expression : %s", c.ConditionalFilter)

			ret, err := exprhelpers.Run(c.ConditionalFilterRuntime,
				map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l},
				l.logger, b.Debug)
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
}
