package bayesiantrain

import (
	"fmt"
	"sync"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type LogEventStorage struct {
	ParsedIpEvents   map[string]fakeBucket
	CachedHypotheses map[string]BayesianResult
	labeled          bool
	total            int
	nEvilIps         int
	nBenignIps       int
	exprCache        map[string]vm.Program
	exprCacheLock    sync.Mutex
}

type BayesianResult struct {
	condition       string
	Attached        bool
	ProbGivenEvil   float32
	ProbGivenBenign float32
}

type evalIpResult struct {
	Result int
	Label  int
	Error  error
}

type evalHypothesisResult struct {
	EvilIpsWithHypothesis   int
	BenignIpsWithHypothesis int
	Error                   error
}

func evaluateProgramOnBucket(l *fakeBucket, compiledExpr *vm.Program, outputChan chan<- evalIpResult) {
	var hypothesis, ok bool
	var queue leakybucket.Queue

	result := 0
	for index, evt := range l.events {
		queue = leakybucket.Queue{Queue: l.events, L: index + 1}
		ret, err := expr.Run(compiledExpr, map[string]interface{}{"evt": &evt, "queue": &queue, "leaky": (*l).leaky})
		if err != nil {
			outputChan <- evalIpResult{Error: err}
			break
		}

		if hypothesis, ok = ret.(bool); !ok {
			outputChan <- evalIpResult{Error: fmt.Errorf("bayesion hypothesis, unexpected non-bool return : %T", ret)}
			break
		}

		if hypothesis {
			result = 1
			break
		}
	}

	outputChan <- evalIpResult{Result: result, Label: l.label}
}

func evaluateSingleProgramOnBucket(l *fakeBucket, compiledExpr *vm.Program) evalIpResult {
	var hypothesis, ok bool
	var queue leakybucket.Queue

	result := 0
	for index, evt := range l.events {
		queue = leakybucket.Queue{Queue: l.events[:index], L: index + 1}
		ret, err := expr.Run(compiledExpr, map[string]interface{}{"evt": &evt, "queue": &queue, "leaky": (*l).leaky})
		if err != nil {
			return evalIpResult{Error: err}
		}

		if hypothesis, ok = ret.(bool); !ok {
			return evalIpResult{Error: fmt.Errorf("bayesion hypothesis, unexpected non-bool return : %T", ret)}
		}

		if hypothesis {
			result = 1
			break
		}
	}

	return evalIpResult{Result: result, Label: l.label}
}

func controllerRoutine(inputChan <-chan evalIpResult, outputChan chan<- evalHypothesisResult, totalIps int) {

	var evilIpsWithHypothesis = 0
	var benignIpsWithHypothesis = 0
	var totalIpsSeen = 0
	for {
		result := <-inputChan

		if result.Error != nil {
			outputChan <- evalHypothesisResult{Error: result.Error}
			break
		}

		if result.Label == 0 {
			benignIpsWithHypothesis += result.Result
		}
		if result.Label == 1 {
			evilIpsWithHypothesis += result.Result
		}
		totalIpsSeen += 1

		if totalIpsSeen == totalIps {
			break
		}
	}

	outputChan <- evalHypothesisResult{EvilIpsWithHypothesis: evilIpsWithHypothesis, BenignIpsWithHypothesis: benignIpsWithHypothesis, Error: nil}
}

func (s *LogEventStorage) InsertLabels(evilIps []string) {

	var nUsedLabels = 0
	for _, ip := range evilIps {
		if parsedEvent, ok := s.ParsedIpEvents[ip]; ok {
			parsedEvent.label = 1
			s.ParsedIpEvents[ip] = parsedEvent
			nUsedLabels += 1
		}
	}
	s.nEvilIps = nUsedLabels
	s.nBenignIps = s.total - s.nEvilIps
	s.labeled = true
}

func (s *LogEventStorage) GenerateBucketMetrics(threshold float32) error {
	var res int
	var falsePositive int
	var falseNegative int
	var truePositive int
	var trueNegative int
	var inferenceChannel chan inferenceResult

	inferenceChannel = make(chan inferenceResult, 20)
	prior := float32(s.nEvilIps) / float32(s.total)

	go saveResultsToDisk(inferenceChannel)

	for _, bucket := range s.ParsedIpEvents {

		res = bucket.scoreTrainedClassifier(s.CachedHypotheses, s.exprCache, prior, threshold, inferenceChannel)
		if res < 0 {
			return fmt.Errorf("generatebucketmetrics returned an error, aborting")
		}
		if bucket.label == 1 {
			if res == 1 {
				truePositive += 1
			} else {
				falseNegative += 1
			}
		} else {
			if res == 1 {
				falsePositive += 1
			} else {
				trueNegative += 1
			}
		}
	}

	close(inferenceChannel)

	fmt.Println("raw : ", falsePositive, falseNegative, truePositive, trueNegative)
	printBucketMetrics(falsePositive, falseNegative, truePositive, trueNegative)

	return nil
}

func printBucketMetrics(falsePositive, falseNegative, truePositive, trueNegative int) {
	fmt.Printf("Precision: %v\n", float32(truePositive)/float32(truePositive+falsePositive))
	fmt.Printf("Recall: %v\n", float32(truePositive)/float32(truePositive+falseNegative))
}

func (s *LogEventStorage) TestHypothesisSingle(hypothesis string) error {
	var result evalIpResult
	var evilIpsWithHypothesis = 0
	var benignIpsWithHypothesis = 0

	if !s.labeled {
		return fmt.Errorf("LogEventStorage has not been labeled yet, add labels using InsertLabels")
	}
	err := compileAndCacheExpr(hypothesis, s)
	if err != nil {
		return err
	}
	condition := s.exprCache[hypothesis]

	for _, v := range s.ParsedIpEvents {

		result = evaluateSingleProgramOnBucket(&v, &condition)
		if result.Error != nil {
			return result.Error
		}

		if result.Label == 0 {
			benignIpsWithHypothesis += result.Result
		}
		if result.Label == 1 {
			evilIpsWithHypothesis += result.Result
		}
	}

	bayesian := BayesianResult{condition: hypothesis, ProbGivenEvil: float32(evilIpsWithHypothesis) / float32(s.nEvilIps), ProbGivenBenign: float32(benignIpsWithHypothesis) / float32(s.nBenignIps)}

	bayesian.printResults()
	s.CachedHypotheses[hypothesis] = bayesian

	fmt.Printf("Finished Hypothesis testing, evil ips with hypothesis %v benign ips with hypothesis %v\n", evilIpsWithHypothesis, benignIpsWithHypothesis)

	return nil
}

func (s *LogEventStorage) AttachHypothesis(hypothesis string) error {

	var res BayesianResult
	var ok bool

	res, ok = s.CachedHypotheses[hypothesis]
	if !ok {
		fmt.Printf("Hypothesis %s was not found in cache, running a training loop\n", hypothesis)
		err := s.TestHypothesisSingle(hypothesis)
		if err != nil {
			return fmt.Errorf("failed to train hypothesis, train loop returned %s", err)
		}
		res = s.CachedHypotheses[hypothesis]
	}

	res.Attached = true
	s.CachedHypotheses[hypothesis] = res
	return nil
}

func (s *LogEventStorage) TestHypothesis(hypothesis string) error {

	if !s.labeled {
		return fmt.Errorf("LogEventStorage has not been labeled yet, add labels using InsertLabels")
	}
	err := compileAndCacheExpr(hypothesis, s)
	if err != nil {
		return err
	}
	condition := s.exprCache[hypothesis]

	inputChan := make(chan evalIpResult, 1000)
	outputChan := make(chan evalHypothesisResult)

	for _, v := range s.ParsedIpEvents {
		go evaluateProgramOnBucket(&v, &condition, inputChan)
	}

	go controllerRoutine(inputChan, outputChan, s.total)

	result := <-outputChan

	if result.Error != nil {
		return result.Error
	}

	bayesian := BayesianResult{condition: hypothesis, ProbGivenEvil: float32(result.EvilIpsWithHypothesis) / float32(s.nEvilIps), ProbGivenBenign: float32(result.BenignIpsWithHypothesis) / float32(s.nBenignIps)}

	bayesian.printResults()

	fmt.Printf("Finished Hypothesis testing, evil ips with hypothesis %v benign ips with hypothesis %v", result.EvilIpsWithHypothesis, result.BenignIpsWithHypothesis)

	return nil
}

func compileAndCacheExpr(hypothesis string, s *LogEventStorage) error {

	var compiledExpr *vm.Program
	var err error

	s.exprCacheLock.Lock()
	if _, ok := s.exprCache[hypothesis]; ok {
		s.exprCacheLock.Unlock()
		return nil
	}
	s.exprCacheLock.Unlock()
	compiledExpr, err = expr.Compile(hypothesis, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &leakybucket.Queue{}, "leaky": &leakybucket.Leaky{}, "evt": &types.Event{}})...)
	if err != nil {
		return fmt.Errorf("hypothesis compile error : %w", err)
	}
	s.exprCacheLock.Lock()
	s.exprCache[hypothesis] = *compiledExpr
	s.exprCacheLock.Unlock()
	return nil
}

func (b *BayesianResult) printResults() {
	fmt.Printf("- condition: %s\n", b.condition)
	fmt.Printf("  prob_given_evil: %v\n", b.ProbGivenEvil)
	fmt.Printf("  prob_given_benign: %v\n", b.ProbGivenBenign)
	fmt.Printf("  guillotine: true\n")
}
