package exprhelpers

import (
	"fmt"
	"strings"

	"github.com/antonmedv/expr/parser"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/vm"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

type Visitor struct {
	newVar     bool
	currentID  string
	properties []string
	vars       []string
}

func (v *Visitor) Enter(node *ast.Node) {}
func (v *Visitor) Exit(node *ast.Node) {
	if n, ok := (*node).(*ast.IdentifierNode); ok {
		if !v.newVar {
			v.newVar = true
			v.currentID = n.Value
		} else {
			v.newVar = false
			fullVar := fmt.Sprintf("%s.%s", v.currentID, strings.Join(v.properties, "."))
			v.vars = append(v.vars, fullVar)
			v.properties = []string{}
			v.currentID = n.Value
		}
	}
	if n, ok := (*node).(*ast.PropertyNode); ok {
		v.properties = append(v.properties, n.Property)
	}
}

func (v *Visitor) Build(filter string) ([]*DebugExpr, error) {
	var ret []*DebugExpr
	v.newVar = false
	tree, err := parser.Parse(filter)
	if err != nil {
		return nil, err
	}
	ast.Walk(&tree.Node, v)
	fullVar := fmt.Sprintf("%s.%s", v.currentID, strings.Join(v.properties, "."))
	v.vars = append(v.vars, fullVar)
	v.properties = []string{}
	v.currentID = ""
	for _, variable := range v.vars {
		debugFilter, err := expr.Compile(variable, expr.Env(GetExprEnv(map[string]interface{}{"evt": &types.Event{}})))
		debugExpr := &DebugExpr{
			variable,
			debugFilter,
		}
		ret = append(ret, debugExpr)
		if err != nil {
			return nil, fmt.Errorf("compilation of variable '%s' failed: %v", variable, err)
		}
	}
	return ret, nil
}

type DebugExpr struct {
	DebugStr  string
	DebugExpr *vm.Program
}
