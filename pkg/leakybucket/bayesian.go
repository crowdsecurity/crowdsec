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
	ProbGivenEvil         float32 `yaml:"prob_given_evil"`
	ProbGivenBenign       float32 `yaml:"prob_given_benign"`
	Guillotine            bool    `yaml:"guillotine,omitempty"`
}

type BayesianEvent struct {
	rawCondition             RawBayesianCondition
	conditionalFilterRuntime *vm.Program
	guillotineState          bool
}

type BayesianBucket struct {
	bayesianEventArray []*BayesianEvent
	prior              float32
	threshold          float32
	posterior          float32
	DumbProcessor
}

func updateProbability(prior, probGivenEvil, ProbGivenBenign float32) float32 {
	numerator := probGivenEvil * prior
	denominator := numerator + ProbGivenBenign*(1-prior)

	return numerator / denominator
}

func (c *BayesianBucket) OnBucketInit(g *BucketFactory) error {
	var err error
	BayesianEventArray := make([]*BayesianEvent, len(g.BayesianConditions))

	if conditionalExprCache == nil {
		conditionalExprCache = make(map[string]vm.Program)
	}
	conditionalExprCacheLock.Lock()

	for index, bcond := range g.BayesianConditions {
		var bayesianEvent BayesianEvent
		bayesianEvent.rawCondition = bcond
		err = bayesianEvent.compileCondition()
		if err != nil {
			return err
		}
		BayesianEventArray[index] = &bayesianEvent
	}
	conditionalExprCacheLock.Unlock()
	c.bayesianEventArray = BayesianEventArray

	c.prior = g.BayesianPrior
	c.threshold = g.BayesianThreshold

	return err
}

func (c *BayesianBucket) AfterBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {
		c.posterior = c.prior
		l.logger.Debugf("starting bayesian evaluation with prior: %v", c.posterior)

		for _, bevent := range c.bayesianEventArray {
			err := bevent.bayesianUpdate(c, msg, l)
			if err != nil {
				l.logger.Errorf("bayesian update failed for %s with %s", bevent.rawCondition.ConditionalFilterName, err)
			}
		}

		l.logger.Debugf("value of posterior after events : %v", c.posterior)

		if c.posterior > c.threshold {
			l.logger.Debugf("Bayesian bucket overflow")
			l.Ovflw_ts = l.Last_ts
			l.Out <- l.Queue
			return nil
		}

		return &msg
	}
}

func (b *BayesianEvent) bayesianUpdate(c *BayesianBucket, msg types.Event, l *Leaky) error {
	var condition, ok bool

	if b.conditionalFilterRuntime == nil {
		l.logger.Tracef("empty conditional filter runtime for %s", b.rawCondition.ConditionalFilterName)
		return nil
	}

	l.logger.Tracef("guillotine value for %s :  %v", b.rawCondition.ConditionalFilterName, b.getGuillotineState())
	if b.getGuillotineState() {
		l.logger.Tracef("guillotine already triggered for %s", b.rawCondition.ConditionalFilterName)
		l.logger.Tracef("condition true updating prior for: %s", b.rawCondition.ConditionalFilterName)
		c.posterior = updateProbability(c.posterior, b.rawCondition.ProbGivenEvil, b.rawCondition.ProbGivenBenign)
		l.logger.Tracef("new value of posterior : %v", c.posterior)
		return nil
	}

	l.logger.Debugf("running condition expression: %s", b.rawCondition.ConditionalFilterName)
	ret, err := exprhelpers.Run(b.conditionalFilterRuntime, map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l}, l.logger, l.BucketConfig.Debug)
	if err != nil {
		return fmt.Errorf("unable to run conditional filter: %s", err)
	}

	l.logger.Tracef("bayesian bucket expression %s returned : %v", b.rawCondition.ConditionalFilterName, ret)
	if condition, ok = ret.(bool); !ok {
		return fmt.Errorf("bayesian condition unexpected non-bool return: %T", ret)
	}

	l.logger.Tracef("condition %T updating prior for: %s", condition, b.rawCondition.ConditionalFilterName)
	if condition {
		c.posterior = updateProbability(c.posterior, b.rawCondition.ProbGivenEvil, b.rawCondition.ProbGivenBenign)
		b.triggerGuillotine()
	} else {
		c.posterior = updateProbability(c.posterior, 1-b.rawCondition.ProbGivenEvil, 1-b.rawCondition.ProbGivenBenign)
	}
	l.logger.Tracef("new value of posterior: %v", c.posterior)

	return nil
}

func (b *BayesianEvent) getGuillotineState() bool {
	if b.rawCondition.Guillotine {
		return b.guillotineState
	}
	return false
}

func (b *BayesianEvent) triggerGuillotine() {
	b.guillotineState = true
}

func (b *BayesianEvent) compileCondition() error {
	var err error
	var compiledExpr *vm.Program

	if compiled, ok := conditionalExprCache[b.rawCondition.ConditionalFilterName]; ok {
		b.conditionalFilterRuntime = &compiled
		return nil
	}

	conditionalExprCacheLock.Unlock()
	//release the lock during compile same as coditional bucket
	compiledExpr, err = expr.Compile(b.rawCondition.ConditionalFilterName, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &types.Queue{}, "leaky": &Leaky{}, "evt": &types.Event{}})...)
	if err != nil {
		return fmt.Errorf("bayesian condition compile error: %w", err)
	}
	b.conditionalFilterRuntime = compiledExpr
	conditionalExprCacheLock.Lock()
	conditionalExprCache[b.rawCondition.ConditionalFilterName] = *compiledExpr

	return nil
}
