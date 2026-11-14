package leakybucket

import (
	"maps"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/crowdsecurity/crowdsec/pkg/exprhelpers"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

// compile returns a compiled expression using the default leakybucket evaluation environment.
//
// It always provides "evt" and merges any additional variables from "extra".
func compile(ex string, extra map[string]any) (*vm.Program, error) {
	env := map[string]any{
		"evt": &pipeline.Event{},
	}

	if extra != nil {
		maps.Copy(env, extra)
	}

	return expr.Compile(ex, exprhelpers.GetExprOptions(env)...)
}
