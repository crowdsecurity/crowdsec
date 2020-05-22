package leakybucket

import (
	"fmt"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/types"
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
	u.FilterRuntime, err = expr.Compile(u.Filter, expr.Env(exprhelpers.GetExprEnv(map[string]interface{}{
		"queue": &Queue{}, "signal": &types.SignalOccurence{}, "leaky": &Leaky{}})))
	if err != nil {
		g.logger.Errorf("Unable to compile filter : %v", err)
		return nil, fmt.Errorf("unable to compile filter : %v", err)
	}
	return &u, nil
}

func (u *OverflowFilter) OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.SignalOccurence, *Queue) (types.SignalOccurence, *Queue) {
	return func(l *Leaky, s types.SignalOccurence, q *Queue) (types.SignalOccurence, *Queue) {
		el, err := expr.Run(u.FilterRuntime, exprhelpers.GetExprEnv(map[string]interface{}{
			"queue": q, "signal": s, "leaky": l}))
		if err != nil {
			l.logger.Errorf("Failed running overflow filter: %s", err)
			return s, q
		}
		element, ok := el.(bool)
		if !ok {
			l.logger.Errorf("Overflow filter didn't return bool: %s", err)
			return s, q
		}
		/*filter returned false, event is blackholded*/
		if !element {
			l.logger.Infof("Event is discard by overflow filter (%s)", u.Filter)
			return types.SignalOccurence{
				MapKey: l.Mapkey,
				// BucketConfiguration: bcfg,
			}, nil
		} else {
			l.logger.Debugf("Event is not discard by overflow filter (%s)", u.Filter)
		}
		return s, q
	}
}
