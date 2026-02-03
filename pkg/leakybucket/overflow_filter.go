package leakybucket

import (
	"fmt"

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
	var err error

	u := OverflowProcessor{}

	u.Filter = f.OverflowFilter

	u.FilterRuntime, err = compile(u.Filter, map[string]any{"queue": &pipeline.Queue{}, "signal": &pipeline.RuntimeAlert{}, "leaky": &Leaky{}})
	if err != nil {
		f.logger.Errorf("Unable to compile filter : %v", err)
		return nil, fmt.Errorf("unable to compile filter : %v", err)
	}
	return &u, nil
}

func (u *OverflowProcessor) OnBucketOverflow(f *BucketFactory, l *Leaky, s pipeline.RuntimeAlert, q *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	el, err := exprhelpers.Run(u.FilterRuntime, map[string]any{
		"queue": q, "signal": s, "leaky": l}, l.logger, f.Debug)
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
		l.logger.Infof("Event is discarded by overflow filter (%s)", u.Filter)
		return pipeline.RuntimeAlert{
			Mapkey: l.Mapkey,
		}, nil
	}
	l.logger.Tracef("Event is not discarded by overflow filter (%s)", u.Filter)
	return s, q
}
