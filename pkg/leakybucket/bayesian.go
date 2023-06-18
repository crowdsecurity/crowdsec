package leakybucket

import (
	"fmt"
	"time"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type RawBayesianCondition struct {
	ConditionalFilterName string  `yaml:"condition"`
	Prob_given_evil       float32 `yaml:"prob_given_evil"`
	Prob_given_benign     float32 `yaml:"prob_given_benign"`
	Guillotine            bool    `yaml:"guillotine,omitempty"`
}

type BayesianEvent struct {
	ConditionalFilterName    string
	ConditionalFilterRuntime *vm.Program
	Prob_given_evil          float32
	Prob_given_benign        float32
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
		bayesianEvent.Prob_given_benign = bcond.Prob_given_benign
		bayesianEvent.Prob_given_evil = bcond.Prob_given_evil
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

		l.logger.Debugf("%s starting bayesian evaluation with prior : %v", time.Now(), c.posterior)

		for _, bevent := range c.BayesianEventArray {

			if bevent.ConditionalFilterRuntime != nil {

				l.logger.Debugf("Guillotine values for %s : %v and %v", bevent.ConditionalFilterName, bevent.Guillotine, bevent.GetGuillotineState())

				if bevent.Guillotine && bevent.GetGuillotineState() {

					l.logger.Debugf("Guillotine already triggered for %s", bevent.ConditionalFilterName)

					l.logger.Debugf("Condition true updating prior for : %s", bevent.ConditionalFilterName)
					c.posterior = update_probability(c.posterior, bevent.Prob_given_evil, bevent.Prob_given_benign)
					l.logger.Debugf("new value of posterior : %v", c.posterior)
				} else {
					l.logger.Debugf("Running condition expression : %s", bevent.ConditionalFilterName)
					ret, err := expr.Run(bevent.ConditionalFilterRuntime, map[string]interface{}{"evt": &msg, "queue": l.Queue, "leaky": l})
					if err != nil {
						l.logger.Errorf("unable to run conditional filter : %s", err)
						return &msg
					}

					l.logger.Debugf("Bayesian bucket expression %s returned : %v", bevent.ConditionalFilterName, ret)

					if condition, ok = ret.(bool); !ok {
						l.logger.Warningf("bayesian condition unexpected non-bool return : %T", ret)
						return &msg
					}

					if condition {

						if bevent.Guillotine {
							bevent.TriggerGuillotine()
							l.logger.Debugf("%s Triggering guillotine for : %s", time.Now(), bevent.ConditionalFilterName)
							l.logger.Debugf("%s The Guillotine state is now : %v", time.Now(), bevent.GetGuillotineState())
						}

						l.logger.Debugf("Condition true updating prior for : %s", bevent.ConditionalFilterName)
						c.posterior = update_probability(c.posterior, bevent.Prob_given_evil, bevent.Prob_given_benign)
						l.logger.Debugf("new value of posterior : %v", c.posterior)

					} else {
						l.logger.Debugf("Condition false updating prior for : %s", bevent.ConditionalFilterName)
						c.posterior = update_probability(c.posterior, 1-bevent.Prob_given_evil, 1-bevent.Prob_given_benign)
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
		} else {
			l.logger.Debugf("Bayesian bucket under threshold : reseting prior")
			c.posterior = c.Prior
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
