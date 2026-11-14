package appsec

import (
	"context"
	"errors"

	"github.com/expr-lang/expr"
)

// AddRequestScore has two prototypes, only expr.Function accepts more than one per name.
type scoreBindingKey struct{}

type scoreAdder func(points int, label string, category ...string) error

func withScoreBinding(ctx context.Context, w *AppsecRuntimeConfig, state *AppsecRequestState) context.Context {
	add := scoreAdder(func(points int, label string, category ...string) error {
		return w.AddRequestScore(state, points, label, category...)
	})

	return context.WithValue(ctx, scoreBindingKey{}, add)
}

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
	expr.WithContext(requestCtxVar),
}
