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

var exprCache map[string]vm.Program
var exprCacheLock sync.Mutex

type LogEventStorage struct {
	ParsedIpEvents map[string]fakeBucket
	labeled        bool
	total          int
	nEvilIps       int
	nBenignIps     int
}

type fakeBucket struct {
	events []types.Event
	leaky  *leakybucket.Leaky
	label  int
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
	for index, evt := range l.events {
		ret, err := expr.Run(compiledExpr, map[string]interface{}{"evt": &evt, "queue": leakybucket.Queue{Queue: l.events[:index], L: index + 1}, "leaky": &(l.leaky)})
		if err != nil {
			outputChan <- evalIpResult{Error: err}
		}

		if hypothesis, ok = ret.(bool); !ok {
			outputChan <- evalIpResult{Error: fmt.Errorf("bayesion hypothesis, unexpected non-bool return : %T", ret)}
		}

		if hypothesis {
			outputChan <- evalIpResult{Result: 1, Label: l.label}
			break
		}
	}

	outputChan <- evalIpResult{Result: 0, Label: l.label}
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

func (s *LogEventStorage) TestHypothesis(hypothesis string) error {

	if !s.labeled {
		return fmt.Errorf("LogEventStorage has not been labeled yet, add labels using InsertLabels")
	}
	compiled, err := compileAndCacheHypothesis(hypothesis)
	if err != nil {
		return err
	}

	inputChan := make(chan evalIpResult, 1000)
	outputChan := make(chan evalHypothesisResult)
	defer close(inputChan)
	defer close(outputChan)

	for _, v := range s.ParsedIpEvents {
		go evaluateProgramOnBucket(&v, compiled, inputChan)
	}

	go controllerRoutine(inputChan, outputChan, s.total)

	result := <-outputChan

	if result.Error != nil {
		return result.Error
	}

	fmt.Printf("Finished Hypothesis testing, evil ips with hypothesis %v benign ips with hpyothesis %v", result.EvilIpsWithHypothesis, result.BenignIpsWithHypothesis)

	return nil
}

func compileAndCacheHypothesis(hypothesis string) (*vm.Program, error) {

	var compiledExpr *vm.Program
	var err error

	exprCacheLock.Lock()
	if compiled, ok := exprCache[hypothesis]; ok {
		exprCacheLock.Unlock()
		return &compiled, nil
	}
	exprCacheLock.Unlock()
	compiledExpr, err = expr.Compile(hypothesis, exprhelpers.GetExprOptions(map[string]interface{}{"queue": &leakybucket.Queue{}, "leaky": &leakybucket.Leaky{}, "evt": &types.Event{}})...)
	if err != nil {
		return nil, fmt.Errorf("hypothesis compile error : %w", err)
	}
	exprCacheLock.Lock()
	exprCache[hypothesis] = *compiledExpr
	exprCacheLock.Unlock()
	return compiledExpr, nil
}
