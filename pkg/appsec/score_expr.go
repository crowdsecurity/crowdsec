package appsec

import (
	"context"
	"errors"
	"fmt"

	"github.com/expr-lang/expr"
)

// scoreCtxVar names the env variable expr.WithContext injects as the hidden
// first argument of AddRequestScore. Underscore-prefixed because it is wiring:
// rules never write it.
const scoreCtxVar = "_score_ctx"

// AddRequestScore is the one score helper with two prototypes (the category is
// optional), and only expr.Function accepts more than one per name. That
// registration happens once at compile time, so it cannot close over the
// per-request state the way the other helpers do — the state travels through
// the context that expr.WithContext threads in.
//
// Every other score helper has a single prototype and is a plain closure in the
// stage env maps, where it closes over the state directly.
type scoreBindingKey struct{}

type scoreBinding struct {
	w     *AppsecRuntimeConfig
	state *AppsecRequestState
}

func withScoreBinding(ctx context.Context, w *AppsecRuntimeConfig, state *AppsecRequestState) context.Context {
	return context.WithValue(ctx, scoreBindingKey{}, &scoreBinding{w: w, state: state})
}

func scoreBindingFrom(params []any) (*scoreBinding, error) {
	if len(params) == 0 {
		return nil, errors.New("AddRequestScore called without a context")
	}

	ctx, ok := params[0].(context.Context)
	if !ok {
		return nil, fmt.Errorf("AddRequestScore got %T where a context was expected", params[0])
	}

	binding, _ := ctx.Value(scoreBindingKey{}).(*scoreBinding)
	if binding == nil || binding.state == nil || binding.w == nil {
		return nil, errors.New("request score is not available in this hook")
	}

	return binding, nil
}

// The registered prototypes make expr reject wrong types and wrong arity at
// config load, so these casts only fail if a prototype and the implementation
// disagree. They are still checked: a panic here would take down the request.
func exprAddRequestScore(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	points, ok := params[1].(int)
	if !ok {
		return nil, fmt.Errorf("AddRequestScore points: expected an integer, got %T", params[1])
	}

	label, ok := params[2].(string)
	if !ok {
		return nil, fmt.Errorf("AddRequestScore label: expected a string, got %T", params[2])
	}

	category := make([]string, 0, 1)

	if len(params) > 3 {
		c, ok := params[3].(string)
		if !ok {
			return nil, fmt.Errorf("AddRequestScore category: expected a string, got %T", params[3])
		}

		category = append(category, c)
	}

	return nil, binding.w.AddRequestScore(binding.state, points, label, category...)
}

// scoreExprOptions is appended per stage rather than registered globally so the
// env map stays the allowlist it has always been — on_load, which has no request
// to score, does not get it.
var scoreExprOptions = []expr.Option{
	expr.Function("AddRequestScore", exprAddRequestScore,
		new(func(context.Context, int, string) error),
		new(func(context.Context, int, string, string) error),
	),
	expr.WithContext(scoreCtxVar),
}
