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
	posLabelCount  int
	posLabelMutex  sync.Mutex
	negLabelCount  int
	negLabelMutex  sync.Mutex
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

func evaluateProgramOnBucket(l *fakeBucket, compiledExpr *vm.Program, posLabelCount *int, posLabelMutex *sync.Mutex, negLabelCount *int, negLabelMutex *sync.Mutex) error {
	var hypothesis, ok bool
	for index, evt := range l.events {
		ret, err := expr.Run(compiledExpr, map[string]interface{}{"evt": &evt, "queue": leakybucket.Queue{Queue: l.events[:index], L: index + 1}, "leaky": &(l.leaky)})
		if err != nil {
			return fmt.Errorf("unable to run conditional filter : %s", err)
		}

		if hypothesis, ok = ret.(bool); !ok {
			return fmt.Errorf("bayesion hypothesis, unexpected non-bool return : %T", ret)
		}

		if hypothesis {
			posLabelMutex.Unlock()
			*posLabelCount = *posLabelCount + 1
			posLabelMutex.Lock()
			return nil
		}
	}
	negLabelMutex.Unlock()
	*negLabelCount = *negLabelCount + 1
	negLabelMutex.Lock()
	return nil
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
		return fmt.Errorf("LogEventStorage has not been labeled yet, add labels using InserLabels")
	}
	compiled, err := compileAndCacheHypothesis(hypothesis)
	if err != nil {
		return err
	}

	s.negLabelCount = 0
	s.posLabelCount = 0
	s.negLabelMutex.Lock()
	s.posLabelMutex.Lock()
	for _, v := range s.ParsedIpEvents {
		go evaluateProgramOnBucket(&v, compiled, &s.posLabelCount, &s.posLabelMutex, &s.negLabelCount, &s.negLabelMutex)
	}
	s.negLabelMutex.Unlock()
	s.negLabelMutex.Unlock()

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
