package appsec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
)

// scoreCtxVar names the env variable expr.WithContext injects as the hidden
// first argument of every request-score helper. Underscore-prefixed because
// it is wiring: rules never write it.
const scoreCtxVar = "_score_ctx"

// The score helpers are registered with expr.Function instead of being
// env-map closures because only expr.Function accepts more than one prototype
// per name. That registration happens once at compile time, so it cannot
// close over the per-request state the way the env-map helpers do — the state
// travels through the context that expr.WithContext threads in.
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
		return nil, errors.New("request score helper called without a context")
	}

	ctx, ok := params[0].(context.Context)
	if !ok {
		return nil, fmt.Errorf("request score helper got %T where a context was expected", params[0])
	}

	binding, _ := ctx.Value(scoreBindingKey{}).(*scoreBinding)
	if binding == nil || binding.state == nil || binding.w == nil {
		return nil, errors.New("request score is not available in this hook")
	}

	return binding, nil
}

// The registered prototypes make expr reject wrong types and wrong arity at
// config load, so these casts only fail if a prototype and its implementation
// disagree. They are still checked: a panic here would take down the request.
func scoreInt(v any) (int, error) {
	i, ok := v.(int)
	if !ok {
		return 0, fmt.Errorf("expected an integer, got %T", v)
	}

	return i, nil
}

func scoreString(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("expected a string, got %T", v)
	}

	return s, nil
}

// expr flattens variadic arguments into params rather than passing a slice.
func scoreStrings(params []any) ([]string, error) {
	out := make([]string, 0, len(params))

	for _, p := range params {
		s, err := scoreString(p)
		if err != nil {
			return nil, err
		}

		out = append(out, s)
	}

	return out, nil
}

// An empty category matches nothing, and no rule means that — omitting the
// argument is how you say "no category". Warn rather than return an error:
// an error from a helper aborts the rest of the hook chain, which is a far
// worse outcome than a rule that scores zero.
func warnEmptyCategory(binding *scoreBinding, helper string, categories []string) {
	if binding.w.Logger == nil {
		return
	}

	for _, c := range categories {
		if strings.TrimSpace(c) == "" {
			binding.w.Logger.Warnf("%s: empty category argument, omit it to mean no category", helper)
			return
		}
	}
}

func exprAddRequestScore(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	points, err := scoreInt(params[1])
	if err != nil {
		return nil, fmt.Errorf("AddRequestScore points: %w", err)
	}

	label, err := scoreString(params[2])
	if err != nil {
		return nil, fmt.Errorf("AddRequestScore label: %w", err)
	}

	category, err := scoreStrings(params[3:])
	if err != nil {
		return nil, fmt.Errorf("AddRequestScore category: %w", err)
	}

	warnEmptyCategory(binding, "AddRequestScore", category)

	return nil, binding.w.AddRequestScore(binding.state, points, label, category...)
}

func exprSetRequestScore(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	points, err := scoreInt(params[1])
	if err != nil {
		return nil, fmt.Errorf("SetRequestScore points: %w", err)
	}

	categories, err := scoreStrings(params[2:])
	if err != nil {
		return nil, fmt.Errorf("SetRequestScore categories: %w", err)
	}

	warnEmptyCategory(binding, "SetRequestScore", categories)

	return nil, binding.w.SetRequestScore(binding.state, points, categories...)
}

func exprRequestScore(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	categories, err := scoreStrings(params[1:])
	if err != nil {
		return nil, fmt.Errorf("RequestScore categories: %w", err)
	}

	warnEmptyCategory(binding, "RequestScore", categories)

	return binding.state.RequestScore.ForCategories(categories...), nil
}

func exprRequestScoreUncategorized(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	return binding.state.RequestScore.Uncategorized(), nil
}

func exprRequestScoreCategories(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	// Never nil: a rule doing `"x" in RequestScoreCategories()` runs on
	// requests that have not been scored yet.
	if categories := binding.state.RequestScore.Categories(); categories != nil {
		return categories, nil
	}

	return []string{}, nil
}

func exprRequestScoreFor(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	label, err := scoreString(params[1])
	if err != nil {
		return nil, fmt.Errorf("RequestScoreFor label: %w", err)
	}

	return binding.state.RequestScore.For(label), nil
}

func exprRequestScoreReasons(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	return binding.state.RequestScore.Reasons(), nil
}

func exprRequestScoreDetail(params ...any) (any, error) {
	binding, err := scoreBindingFrom(params)
	if err != nil {
		return nil, err
	}

	return binding.state.RequestScore.String(), nil
}

// scoreExprOptions exposes the request-score family to a hook stage. It is
// appended per stage rather than registered globally so the env map stays the
// allowlist it has always been — on_load, which has no request to score, does
// not get it.
var scoreExprOptions = []expr.Option{
	expr.Function("AddRequestScore", exprAddRequestScore,
		new(func(context.Context, int, string) error),
		new(func(context.Context, int, string, string) error),
	),
	expr.Function("SetRequestScore", exprSetRequestScore,
		new(func(context.Context, int, ...string) error),
	),
	expr.Function("RequestScore", exprRequestScore,
		new(func(context.Context, ...string) int),
	),
	expr.Function("RequestScoreUncategorized", exprRequestScoreUncategorized,
		new(func(context.Context) int),
	),
	// The handle for a signal scored at 0 to record itself without moving the
	// decision: every score read returns 0, so the category list is the only
	// way a rule can tell it fired.
	expr.Function("RequestScoreCategories", exprRequestScoreCategories,
		new(func(context.Context) []string),
	),
	expr.Function("RequestScoreFor", exprRequestScoreFor,
		new(func(context.Context, string) int),
	),
	expr.Function("RequestScoreReasons", exprRequestScoreReasons,
		new(func(context.Context) []string),
	),
	expr.Function("RequestScoreDetail", exprRequestScoreDetail,
		new(func(context.Context) string),
	),
	expr.WithContext(scoreCtxVar),
}
