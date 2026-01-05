package leakybucket

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
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

func updateProbability(prior, probGivenEvil, probGivenBenign float32) float32 {
	numerator := probGivenEvil * prior
	denominator := numerator + probGivenBenign*(1-prior)

	return numerator / denominator
}

func (c *BayesianBucket) OnBucketInit(g *BucketFactory) error {
	var err error
	bayesianEventArray := make([]*BayesianEvent, len(g.BayesianConditions))

	for index, bcond := range g.BayesianConditions {
		var bayesianEvent BayesianEvent
		bayesianEvent.rawCondition = bcond
		prog, err := bayesianEvent.compileCondition()
		if err != nil {
			return err
		}
		bayesianEvent.conditionalFilterRuntime = prog
		bayesianEventArray[index] = &bayesianEvent
	}
	c.bayesianEventArray = bayesianEventArray

	c.prior = g.BayesianPrior
	c.threshold = g.BayesianThreshold

	return err
}

func (c *BayesianBucket) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, l *Leaky) *pipeline.Event {
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

func (b *BayesianEvent) bayesianUpdate(c *BayesianBucket, msg pipeline.Event, l *Leaky) error {
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
	ret, err := exprhelpers.Run(b.conditionalFilterRuntime, map[string]any{"evt": &msg, "queue": l.Queue, "leaky": l}, l.logger, l.BucketConfig.Debug)
	if err != nil {
		return fmt.Errorf("unable to run conditional filter: %w", err)
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

func (b *BayesianEvent) compileCondition() (*vm.Program, error) {
	name := b.rawCondition.ConditionalFilterName

	conditionalExprCacheLock.Lock()
	prog, ok := conditionalExprCache[name]
	conditionalExprCacheLock.Unlock()
	if ok {
		return prog, nil
	}

	// don't hold lock during compile
	compiled, err := expr.Compile(name, exprhelpers.GetExprOptions(map[string]any{"queue": &pipeline.Queue{}, "leaky": &Leaky{}, "evt": &pipeline.Event{}})...)
	if err != nil {
		return nil, fmt.Errorf("bayesian condition compile error: %w", err)
	}

	// re-check under lock in case of race, avoid double compilation
	conditionalExprCacheLock.Lock()
	if prog2, ok := conditionalExprCache[name]; ok {
		conditionalExprCacheLock.Unlock()
		return prog2, nil
	}

	conditionalExprCache[name] = compiled
	conditionalExprCacheLock.Unlock()

	return compiled, nil
}
