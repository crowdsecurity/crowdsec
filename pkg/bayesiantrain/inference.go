package bayesiantrain

import (
	"fmt"
	"os"

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

type inferenceResult struct {
	ip          string
	prediction  int
	label       int
	probability float32
}

func (f *fakeBucket) scoreTrainedClassifier(results map[string]BayesianResult, exprCache map[string]vm.Program, prior float32, threshold float32, resultChan chan<- inferenceResult) int {
	var posterior float32
	var queue leakybucket.Queue
	var program vm.Program
	var hypothesisValue bool
	var ok bool
	var guillotinecache map[string]bool

	ip := f.events[0].Meta["source_ip"]
	label := f.label
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
			resultChan <- inferenceResult{ip, 1, label, posterior}
			return 1
		}
	}
	resultChan <- inferenceResult{ip, 0, label, posterior}
	return 0
}

func saveResultsToDisk(inputChan <-chan inferenceResult) {
	var res inferenceResult
	var str string
	var more bool

	f, err := os.Create("inference_result.csv")

	if err != nil {
		fmt.Printf("%s", err)
	}

	f.WriteString("ip,probability,label\n")

	defer f.Close()

	for {
		res, more = <-inputChan
		if !more {
			return
		}
		str = fmt.Sprint(res.ip, ",", res.probability, ",", res.label, "\n")
		f.WriteString(str)
	}
}
