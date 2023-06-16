package leakybucket

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type RawBayesianCondition struct {
	ConditionalFilterName string  `yaml:"condition"`
	Prob_given_true       float32 `yaml:"prob_given_true"`
	Prob_given_false      float32 `yaml:"prob_given_false"`
}

type BayesianEvent struct {
	ConditionalFilterName    string
	ConditionalFilterRuntime *vm.Program
	Prob_given_true          float32
	Prob_given_false         float32
}

type BayesianBucket struct {
	BayesianEventArray []BayesianEvent
	DumbProcessor
}

func (c *BayesianBucket) OnBucketInit(g *BucketFactory) error {
	var err error
	var compiledExpr *vm.Program

	n := len(g.BayesianConditions)
	BayesianEventArray := make([]BayesianEvent, n)

	if conditionalExprCache == nil {
		conditionalExprCache = make(map[string]vm.Program)
	}
	conditionalExprCacheLock.Lock()

	for index, bcond := range g.BayesianConditions {
		var bayesianEvent BayesianEvent

		bayesianEvent.ConditionalFilterName = bcond.ConditionalFilterName
		bayesianEvent.Prob_given_false = bcond.Prob_given_false
		bayesianEvent.Prob_given_true = bcond.Prob_given_true

		if compiled, ok := conditionalExprCache[bcond.ConditionalFilterName]; ok {
			bayesianEvent.ConditionalFilterRuntime = &compiled
		} else {
			conditionalExprCacheLock.Unlock()
			//release the lock during compile same as coditional bucket
			compiledExpr, err = expr.Compile(bcond.ConditionalFilterName, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &Queue{}, "leaky": &Leaky{}, "evt": &types.Event{}})...)
			if err != nil {
				return fmt.Errorf("Bayesian condition compile error : %w", err)
			}
			bayesianEvent.ConditionalFilterRuntime = compiledExpr
			conditionalExprCacheLock.Lock()
			conditionalExprCache[bcond.ConditionalFilterName] = *compiledExpr
		}

		BayesianEventArray[index] = bayesianEvent
	}
	conditionalExprCacheLock.Unlock()
	c.BayesianEventArray = BayesianEventArray

	return err
}

func (c *BayesianBucket) AfterBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {
		var condition, ok bool
		if c.ConditionalFilterRuntime != nil {
			l.logger.Debugf("Running condition expression : %s", c.ConditionalFilter)
			ret, err := expr.Run(c.ConditionalFilterRuntime, map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l})
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
