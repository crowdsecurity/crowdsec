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
	ConditionalFilterName    string
	ConditionalFilterRuntime *vm.Program
	ProbGivenEvil            float32
	ProbGivenBenign          float32
	Guillotine               bool
	guillotineState          bool
}

type BayesianBucket struct {
	BayesianEventArray []*BayesianEvent
	Prior              float32
	Threshold          float32
	posterior          float32
	DumbProcessor
}

func updateProbability(prior, prob_given_evil, prob_given_benign float32) float32 {
	numerator := prob_given_evil * prior
	denominator := numerator + prob_given_benign*(1-prior)

	return numerator / denominator
}

func (c *BayesianBucket) OnBucketInit(g *BucketFactory) error {
	var err error
	var compiledExpr *vm.Program

	n := len(g.BayesianConditions)
	BayesianEventArray := make([]*BayesianEvent, n)

	if conditionalExprCache == nil {
		conditionalExprCache = make(map[string]vm.Program)
	}
	conditionalExprCacheLock.Lock()

	for index, bcond := range g.BayesianConditions {
		var bayesianEvent BayesianEvent

		bayesianEvent.ConditionalFilterName = bcond.ConditionalFilterName
		bayesianEvent.ProbGivenBenign = bcond.ProbGivenBenign
		bayesianEvent.ProbGivenEvil = bcond.ProbGivenEvil
		bayesianEvent.Guillotine = bcond.Guillotine

		if compiled, ok := conditionalExprCache[bcond.ConditionalFilterName]; ok {
			bayesianEvent.ConditionalFilterRuntime = &compiled
		} else {
			conditionalExprCacheLock.Unlock()
			//release the lock during compile same as coditional bucket
			compiledExpr, err = expr.Compile(bcond.ConditionalFilterName, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &Queue{}, "leaky": &Leaky{}, "evt": &types.Event{}})...)
			if err != nil {
				return fmt.Errorf("bayesian condition compile error : %w", err)
			}
			bayesianEvent.ConditionalFilterRuntime = compiledExpr
			conditionalExprCacheLock.Lock()
			conditionalExprCache[bcond.ConditionalFilterName] = *compiledExpr
		}

		BayesianEventArray[index] = &bayesianEvent
	}
	conditionalExprCacheLock.Unlock()
	c.BayesianEventArray = BayesianEventArray
	c.Prior = g.BayesianPrior
	c.posterior = g.BayesianPrior
	c.Threshold = g.BayesianThreshold

	return err
}

func (c *BayesianBucket) AfterBucketPour(b *BucketFactory) func(types.Event, *Leaky) *types.Event {
	return func(msg types.Event, l *Leaky) *types.Event {

		l.logger.Tracef("starting bayesian evaluation : reseting posterior")
		c.posterior = c.Prior
		l.logger.Debugf("starting bayesian evaluation with prior : %v", c.posterior)

		for _, bevent := range c.BayesianEventArray {
			err := bevent.bayesianUpdate(c, msg, l)
			if err != nil {
				l.logger.Errorf("bayesian update failed for %s with %s", bevent.ConditionalFilterName, err)
			}
		}

		l.logger.Debugf("value of posterior after events : %v", c.posterior)

		if c.posterior > c.Threshold {
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

	if b.ConditionalFilterRuntime == nil {
		return nil
	}

	l.logger.Tracef("guillotine value for %s :  %v", b.ConditionalFilterName, b.GetGuillotineState())

	if b.GetGuillotineState() {

		l.logger.Tracef("guillotine already triggered for %s", b.ConditionalFilterName)

		l.logger.Tracef("condition true updating prior for : %s", b.ConditionalFilterName)
		c.posterior = updateProbability(c.posterior, b.ProbGivenEvil, b.ProbGivenBenign)
		l.logger.Tracef("new value of posterior : %v", c.posterior)

		return nil
	}

	l.logger.Tracef("running condition expression : %s", b.ConditionalFilterName)
	ret, err := expr.Run(b.ConditionalFilterRuntime, map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l})
	if err != nil {
		l.logger.Errorf("unable to run conditional filter : %s", err)
		return err
	}

	l.logger.Tracef("bayesian bucket expression %s returned : %v", b.ConditionalFilterName, ret)

	if condition, ok = ret.(bool); !ok {
		l.logger.Warningf("bayesian condition unexpected non-bool return : %T", ret)
		return err
	}

	if condition {

		l.logger.Tracef("condition true updating prior for : %s", b.ConditionalFilterName)
		c.posterior = updateProbability(c.posterior, b.ProbGivenEvil, b.ProbGivenBenign)
		l.logger.Tracef("new value of posterior : %v", c.posterior)

		b.TriggerGuillotine()

	} else {
		l.logger.Tracef("condition false updating prior for : %s", b.ConditionalFilterName)
		c.posterior = updateProbability(c.posterior, 1-b.ProbGivenEvil, 1-b.ProbGivenBenign)
		l.logger.Tracef("new value of posterior : %v", c.posterior)
	}

	return nil
}

func (b *BayesianEvent) GetGuillotineState() bool {
	if b.Guillotine {
		return b.guillotineState
	} else {
		return false
	}
}

func (b *BayesianEvent) TriggerGuillotine() {
	b.guillotineState = true
}
