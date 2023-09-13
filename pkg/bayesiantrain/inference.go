package bayesiantrain

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type fakeBucket struct {
	events []types.Event
	leaky  *leakybucket.Leaky
	label  int
}

func (f *fakeBucket) scoreTrainedClassifier(results map[string]BayesianResult, exprCache map[string]vm.Program, prior float32, threshold float32) int {
	var posterior float32
	var queue leakybucket.Queue
	var program vm.Program
	var hypothesisValue bool
	var ok bool
	var guillotinecache map[string]bool

	guillotinecache = make(map[string]bool)

	for index, evt := range f.events {
		queue = leakybucket.Queue{Queue: f.events[:index], L: index + 1}
		posterior = prior

		for hypothesis, result := range results {

			if !result.Attached {
				continue
			}
			if guillotinecache[hypothesis] {
				posterior = leakybucket.UpdateBayesianProbability(posterior, result.ProbGivenEvil, result.ProbGivenBenign)
				continue
			}

			program = exprCache[hypothesis]
			ret, err := expr.Run(&program, map[string]interface{}{"evt": &evt, "queue": &queue, "leaky": f.leaky})
			if err != nil {
				fmt.Errorf("ran into error while evaluating %v on bucket", hypothesis)
				return -1
			}

			if hypothesisValue, ok = ret.(bool); !ok {
				fmt.Errorf("bayesion hypothesis, unexpected non-bool return : %T", ret)
				return -1
			}

			if hypothesisValue {
				guillotinecache[hypothesis] = true
				posterior = leakybucket.UpdateBayesianProbability(posterior, result.ProbGivenEvil, result.ProbGivenBenign)
			} else {
				posterior = leakybucket.UpdateBayesianProbability(posterior, 1-result.ProbGivenEvil, 1-result.ProbGivenBenign)
			}
		}

		if posterior >= threshold {
			return 1
		}
	}

	return 0
}
