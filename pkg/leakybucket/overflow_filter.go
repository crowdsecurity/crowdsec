package leakybucket

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// Uniq creates three new functions that share the same initialisation and the same scope.
// They are triggered respectively:
// on pour
// on overflow
// on leak

type OverflowFilter struct {
	Filter        string
	FilterRuntime *vm.Program
	DumbProcessor
}

func NewOverflowFilter(g *BucketFactory) (*OverflowFilter, error) {
	var err error

	u := OverflowFilter{}
	u.Filter = g.OverflowFilter

	u.FilterRuntime, err = expr.Compile(u.Filter, exprhelpers.GetExprOptions(map[string]any{"queue": &pipeline.Queue{}, "signal": &pipeline.RuntimeAlert{}, "leaky": &Leaky{}})...)
	if err != nil {
		g.logger.Errorf("Unable to compile filter : %v", err)
		return nil, fmt.Errorf("unable to compile filter : %v", err)
	}
	return &u, nil
}

func (u *OverflowFilter) OnBucketOverflow(bucket *BucketFactory, l *Leaky, s pipeline.RuntimeAlert, q *pipeline.Queue) (pipeline.RuntimeAlert, *pipeline.Queue) {
	el, err := exprhelpers.Run(u.FilterRuntime, map[string]any{
		"queue": q, "signal": s, "leaky": l}, l.logger, bucket.Debug)
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
