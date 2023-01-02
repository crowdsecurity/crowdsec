package leakybucket

import (
	"fmt"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type ConditionalOverflow struct {
	ConditionalFilter        string
	ConditionalFilterRuntime *vm.Program
	DumbProcessor
}

func NewConditionalOverflow(g *BucketFactory) (*ConditionalOverflow, error) {
	var err error

	c := ConditionalOverflow{}
	c.ConditionalFilter = g.ConditionalOverflow
	c.ConditionalFilterRuntime, err = expr.Compile(c.ConditionalFilter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{
		"queue": &Queue{}, "leaky": &Leaky{}})))
	if err != nil {
		g.logger.Errorf("Unable to compile conditional filter : %s", err)
		return nil, fmt.Errorf("unable to compile conditional filter : %v", err)
	}
	return &c, nil
}

func (c *ConditionalOverflow) AfterBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {
		var condition, ok bool
		if c.ConditionalFilterRuntime != nil {
			l.logger.Infof("Running conditional filter : %s", c.ConditionalFilter)
			ret, err := expr.Run(c.ConditionalFilterRuntime, exprhelpers.GetExprEnv(map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l}))
			if err != nil {
				l.logger.Errorf("unable to run conditionnal filter : %s", err)
				return &msg
			}

			l.logger.Debugf("Conditional filter returned : %v", ret)

			//l.logger.Infof("queue:")
			//spew.Dump(l.Queue)

			if condition, ok = ret.(bool); !ok {
				l.logger.Warningf("cancel_on, unexpected non-bool return : %T", ret)
				return &msg
			}

			if condition {
				l.logger.Infof("Conditional bucket overflow")
				l.Ovflw_ts = time.Now().UTC()
				l.Out <- l.Queue
				return nil
			}
		}

		return &msg
	}
}
