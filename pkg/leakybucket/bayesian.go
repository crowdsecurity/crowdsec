package leakybucket

import (
	"fmt"

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

type BayesianProcessor struct {
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

func (p *BayesianProcessor) OnBucketInit(f *BucketFactory) error {
	var err error
	bayesianEventArray := make([]*BayesianEvent, len(f.Spec.BayesianConditions))

	for index, bcond := range f.Spec.BayesianConditions {
		prog, err := compileCondition(bcond.ConditionalFilterName)
		if err != nil {
			return err
		}
		bayesianEventArray[index] = &BayesianEvent{
			rawCondition:             bcond,
			conditionalFilterRuntime: prog,
		}
	}
	p.bayesianEventArray = bayesianEventArray

	p.prior = f.Spec.BayesianPrior
	p.threshold = f.Spec.BayesianThreshold

	return err
}

func (p *BayesianProcessor) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, l *Leaky) *pipeline.Event {
	p.posterior = p.prior
	l.logger.Debugf("starting bayesian evaluation with prior: %v", p.posterior)

	for _, bevent := range p.bayesianEventArray {
		err := bevent.bayesianUpdate(p, msg, l)
		if err != nil {
			l.logger.Errorf("bayesian update failed for %s with %s", bevent.rawCondition.ConditionalFilterName, err)
		}
	}

	l.logger.Debugf("value of posterior after events : %v", p.posterior)

	if p.posterior > p.threshold {
		l.logger.Debugf("Bayesian bucket overflow")
		l.Ovflw_ts = l.Last_ts
		l.Out <- l.Queue
		return nil
	}

	return &msg
}

func (e *BayesianEvent) bayesianUpdate(p *BayesianProcessor, msg pipeline.Event, l *Leaky) error {
	var condition, ok bool

	if e.conditionalFilterRuntime == nil {
		l.logger.Tracef("empty conditional filter runtime for %s", e.rawCondition.ConditionalFilterName)
		return nil
	}

	l.logger.Tracef("guillotine value for %s :  %v", e.rawCondition.ConditionalFilterName, e.getGuillotineState())
	if e.getGuillotineState() {
		l.logger.Tracef("guillotine already triggered for %s", e.rawCondition.ConditionalFilterName)
		l.logger.Tracef("condition true updating prior for: %s", e.rawCondition.ConditionalFilterName)
		p.posterior = updateProbability(p.posterior, e.rawCondition.ProbGivenEvil, e.rawCondition.ProbGivenBenign)
		l.logger.Tracef("new value of posterior : %v", p.posterior)
		return nil
	}

	l.logger.Debugf("running condition expression: %s", e.rawCondition.ConditionalFilterName)
	ret, err := exprhelpers.Run(e.conditionalFilterRuntime, map[string]any{"evt": &msg, "queue": l.Queue, "leaky": l}, l.logger, l.Factory.Spec.Debug)
	if err != nil {
		return fmt.Errorf("unable to run conditional filter: %w", err)
	}

	l.logger.Tracef("bayesian bucket expression %s returned : %v", e.rawCondition.ConditionalFilterName, ret)
	if condition, ok = ret.(bool); !ok {
		return fmt.Errorf("bayesian condition unexpected non-bool return: %T", ret)
	}

	l.logger.Tracef("condition %T updating prior for: %s", condition, e.rawCondition.ConditionalFilterName)
	if condition {
		p.posterior = updateProbability(p.posterior, e.rawCondition.ProbGivenEvil, e.rawCondition.ProbGivenBenign)
		e.triggerGuillotine()
	} else {
		p.posterior = updateProbability(p.posterior, 1-e.rawCondition.ProbGivenEvil, 1-e.rawCondition.ProbGivenBenign)
	}
	l.logger.Tracef("new value of posterior: %v", p.posterior)

	return nil
}

func (e *BayesianEvent) getGuillotineState() bool {
	if e.rawCondition.Guillotine {
		return e.guillotineState
	}

	return false
}

func (e *BayesianEvent) triggerGuillotine() {
	e.guillotineState = true
}

func compileCondition(filterName string) (*vm.Program, error) {
	conditionalExprCacheLock.Lock()
	prog, ok := conditionalExprCache[filterName]
	conditionalExprCacheLock.Unlock()
	if ok {
		return prog, nil
	}

	// don't hold lock during compile
	compiled, err := compile(filterName, map[string]any{"queue": &pipeline.Queue{}, "leaky": &Leaky{}})
	if err != nil {
		return nil, fmt.Errorf("bayesian condition compile error: %w", err)
	}

	// re-check under lock in case of race, avoid double compilation
	conditionalExprCacheLock.Lock()
	defer conditionalExprCacheLock.Unlock()

	if prog2, ok := conditionalExprCache[filterName]; ok {
		return prog2, nil
	}

	conditionalExprCache[filterName] = compiled

	return compiled, nil
}
