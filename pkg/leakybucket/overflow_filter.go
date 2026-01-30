package leakybucket

import (
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

type OverflowProcessor struct {
	Filter        string
	FilterRuntime *vm.Program
	DumbProcessor
}

func NewOverflowProcessor(f *BucketFactory) (*OverflowProcessor, error) {
	p := OverflowProcessor{}
	p.Filter = f.Spec.OverflowFilter
	p.FilterRuntime = f.RunTimeOverflowFilter
	return &p, nil
}

func (p *OverflowProcessor) OnBucketOverflow(f *BucketFactory, l *Leaky, s pipeline.RuntimeAlert, q *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	el, err := exprhelpers.Run(p.FilterRuntime, map[string]any{
		"queue": q, "signal": s, "leaky": l}, l.logger, f.Spec.Debug)
	if err != nil {
		l.logger.Errorf("Failed running overflow filter: %s", err)
		return s, q
	}
	element, ok := el.(bool)
	if !ok {
		l.logger.Errorf("Overflow filter didn't return bool: %s", err)
		return s, q
	}
	// filter returned false, event is blackholded
	if !element {
		l.logger.Infof("Event is discarded by overflow filter (%s)", p.Filter)
		return pipeline.RuntimeAlert{
			Mapkey: l.Mapkey,
		}, nil
	}
	l.logger.Tracef("Event is not discarded by overflow filter (%s)", p.Filter)
	return s, q
}
