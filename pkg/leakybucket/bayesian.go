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
	guillotine_state         bool
}

type BayesianBucket struct {
	BayesianEventArray []*BayesianEvent
	Prior              float32
	Threshold          float32
	posterior          float32
	DumbProcessor
}

func update_probability(prior, prob_given_evil, prob_given_benign float32) float32 {
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
		var condition, ok bool

		l.logger.Debugf("starting bayesian evaluation : reseting posterior")
		c.posterior = c.Prior
		l.logger.Debugf("starting bayesian evaluation with prior : %v", c.posterior)

		for _, bevent := range c.BayesianEventArray {

			if bevent.ConditionalFilterRuntime != nil {

				l.logger.Debugf("guillotine values for %s : %v and %v", bevent.ConditionalFilterName, bevent.Guillotine, bevent.GetGuillotineState())

				if bevent.Guillotine && bevent.GetGuillotineState() {

					l.logger.Debugf("guillotine already triggered for %s", bevent.ConditionalFilterName)

					l.logger.Debugf("condition true updating prior for : %s", bevent.ConditionalFilterName)
					c.posterior = update_probability(c.posterior, bevent.ProbGivenEvil, bevent.ProbGivenBenign)
					l.logger.Debugf("new value of posterior : %v", c.posterior)
				} else {
					l.logger.Debugf("running condition expression : %s", bevent.ConditionalFilterName)
					ret, err := expr.Run(bevent.ConditionalFilterRuntime, map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l})
					if err != nil {
						l.logger.Errorf("unable to run conditional filter : %s", err)
						return &msg
					}

					l.logger.Debugf("bayesian bucket expression %s returned : %v", bevent.ConditionalFilterName, ret)

					if condition, ok = ret.(bool); !ok {
						l.logger.Warningf("bayesian condition unexpected non-bool return : %T", ret)
						return &msg
					}

					if condition {

						l.logger.Debugf("condition true updating prior for : %s", bevent.ConditionalFilterName)
						c.posterior = update_probability(c.posterior, bevent.ProbGivenEvil, bevent.ProbGivenBenign)
						l.logger.Debugf("new value of posterior : %v", c.posterior)

						if bevent.Guillotine {
							bevent.TriggerGuillotine()
							l.logger.Debugf("triggering guillotine for : %s", bevent.ConditionalFilterName)
							l.logger.Debugf("the guillotine state is now : %v", bevent.GetGuillotineState())
						}

					} else {
						l.logger.Debugf("condition false updating prior for : %s", bevent.ConditionalFilterName)
						c.posterior = update_probability(c.posterior, 1-bevent.ProbGivenEvil, 1-bevent.ProbGivenBenign)
						l.logger.Debugf("new value of posterior : %v", c.posterior)
					}
				}
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

func (b *BayesianEvent) GetGuillotineState() bool {
	return b.guillotine_state
}

func (b *BayesianEvent) TriggerGuillotine() {
	b.guillotine_state = true
}
