package appsec

import (
	"context"
	"errors"

	"github.com/expr-lang/expr"
)

// scoreCtxVar names the env variable expr.WithContext injects as the hidden
// first argument of AddRequestScore. Underscore-prefixed because it is wiring:
// rules never write it.
const scoreCtxVar = "_score_ctx"

// AddRequestScore is the one score helper with two prototypes (the category is
// optional), and only expr.Function accepts more than one per name. That
// registration happens once at compile time, so it cannot close over the
// per-request state the way the other helpers do — a bound call travels through
// the context that expr.WithContext threads in instead.
//
// Every other score helper has a single prototype and is a plain closure in the
// stage env maps, where it closes over the state directly.
type scoreBindingKey struct{}

type scoreAdder func(points int, label string, category ...string) error

func withScoreBinding(ctx context.Context, w *AppsecRuntimeConfig, state *AppsecRequestState) context.Context {
	add := scoreAdder(func(points int, label string, category ...string) error {
		return w.AddRequestScore(state, points, label, category...)
	})

	return context.WithValue(ctx, scoreBindingKey{}, add)
}

// The registered prototypes already rejected wrong types and wrong arity at
// config load, so the assertions below cannot fail unless a prototype and this
// function disagree. They are left unchecked on purpose: expr's VM recovers a
// panic into an error carrying the rule's source location, which beats any
// message written here.
func exprAddRequestScore(params ...any) (any, error) {
	var add scoreAdder

	if ctx, ok := params[0].(context.Context); ok {
		add, _ = ctx.Value(scoreBindingKey{}).(scoreAdder)
	}

	if add == nil {
		return nil, errors.New("request score is not available in this hook")
	}

	var category []string
	if len(params) > 3 {
		category = append(category, params[3].(string))
	}

	return nil, add(params[1].(int), params[2].(string), category...)
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
