package waf

import (
	"github.com/antonmedv/expr"
	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
)

var exprFunctionOptions []expr.Option

func initWafHelpers() {
	exprFunctionOptions = []expr.Option{}
	for _, function := range exprFuncs {
		exprFunctionOptions = append(exprFunctionOptions,
			expr.Function(function.name,
				function.function,
				function.signature...,
			))
	}
}

func GetExprWAFOptions(ctx map[string]interface{}) []expr.Option {
	baseHelpers := exprhelpers.GetExprOptions(ctx)

	for _, function := range exprFuncs {
		baseHelpers = append(baseHelpers,
			expr.Function(function.name,
				function.function,
				function.signature...,
			))
	}
	return baseHelpers
}

func SetRulesToInband(params ...any) (any, error) {

	return nil, nil
}

func SetRulesToOutOfBand(params ...any) (any, error) {
	return nil, nil
}
