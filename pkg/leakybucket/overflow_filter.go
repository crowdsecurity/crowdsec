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
		"queue": &Queue{}, "signal": &types.RuntimeAlert{}, "leaky": &Leaky{}})))
	if err != nil {
		g.logger.Errorf("Unable to compile filter : %v", err)
		return nil, fmt.Errorf("unable to compile filter : %v", err)
	}
	return &u, nil
}

func (u *OverflowFilter) OnBucketOverflow(Bucket *BucketFactory) func(*Leaky, types.RuntimeAlert, *Queue) (types.RuntimeAlert, *Queue) {
	return func(l *Leaky, s types.RuntimeAlert, q *Queue) (types.RuntimeAlert, *Queue) {
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
			l.logger.Infof("Event is discarded by overflow filter (%s)", u.Filter)
			return types.RuntimeAlert{
				Mapkey: l.Mapkey,
			}, nil
		}
		l.logger.Tracef("Event is not discarded by overflow filter (%s)", u.Filter)
		return s, q
	}
}
