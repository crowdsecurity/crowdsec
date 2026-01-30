package leakybucket

import (
	"sync"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Uniq creates three new functions that share the same initialisation and the same scope.
// They are triggered respectively:
// on pour
// on overflow
// on leak

type UniqProcessor struct {
	DistinctCompiled *vm.Program
	KeyCache         map[string]bool
	CacheMutex       sync.Mutex
}

func NewUniqProcessor(f *BucketFactory) (*UniqProcessor, error) {
	p := UniqProcessor{}
	p.DistinctCompiled = f.RunTimeDistinct
	p.KeyCache = make(map[string]bool)
	return &p, nil
}

func (p *UniqProcessor) OnBucketPour(f *BucketFactory, msg pipeline.Event, leaky *Leaky) *pipeline.Event {
	element, err := getElement(msg, p.DistinctCompiled)
	if err != nil {
		leaky.logger.Errorf("Uniq filter exec failed : %v", err)
		return &msg
	}
	leaky.logger.Tracef("Uniq '%s' -> '%s'", f.Spec.Distinct, element)
	p.CacheMutex.Lock()
	defer p.CacheMutex.Unlock()
	if _, ok := p.KeyCache[element]; !ok {
		leaky.logger.Debugf("Uniq(%s) : ok", element)
		p.KeyCache[element] = true
		return &msg
	}
	leaky.logger.Debugf("Uniq(%s) : ko, discard event", element)
	return nil
}

func (*UniqProcessor) OnBucketOverflow(_ *BucketFactory, _ *Leaky, alert pipeline.RuntimeAlert, queue *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	return alert, queue
}

func (*UniqProcessor) AfterBucketPour(_ *BucketFactory, msg pipeline.Event, _ *Leaky) *pipeline.Event {
	return &msg
}

// getElement computes a string from an event and a filter
func getElement(msg pipeline.Event, cFilter *vm.Program) (string, error) {
	el, err := expr.Run(cFilter, map[string]any{"evt": &msg})
	if err != nil {
		return "", err
	}
	element, ok := el.(string)
	if !ok {
		return "", err
	}
	return element, nil
}
