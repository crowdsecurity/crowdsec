package exprhelpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antonmedv/expr/parser"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/antonmedv/expr"
	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/vm"
)

/*
Visitor is used to reconstruct variables with its property called in an expr filter
Thus, we can debug expr filter by displaying all variables contents present in the filter
*/
type visitor struct {
	newVar    bool
	currentId string
	vars      map[string][]string
	logger    *log.Entry
}

func (v *visitor) Visit(node *ast.Node) {
	switch n := (*node).(type) {
	case *ast.IdentifierNode:
		v.newVar = true
		uid, _ := uuid.NewUUID()
		v.currentId = uid.String()
		v.vars[v.currentId] = []string{n.Value}
	case *ast.MemberNode:
		if n2, ok := n.Property.(*ast.StringNode); ok {
			v.vars[v.currentId] = append(v.vars[v.currentId], n2.Value)
		}
	case *ast.StringNode: //Don't reset here, as any attribute of a member node is a string node (in evt.X, evt is member node, X is string node)
	default:
		v.newVar = false
		v.currentId = ""
		/*case *ast.IntegerNode:
			v.logger.Infof("integer node found: %+v", n)
		case *ast.FloatNode:
			v.logger.Infof("float node found: %+v", n)
		case *ast.BoolNode:
			v.logger.Infof("boolean node found: %+v", n)
		case *ast.ArrayNode:
			v.logger.Infof("array node found: %+v", n)
		case *ast.ConstantNode:
			v.logger.Infof("constant node found: %+v", n)
		case *ast.UnaryNode:
			v.logger.Infof("unary node found: %+v", n)
		case *ast.BinaryNode:
			v.logger.Infof("binary node found: %+v", n)
		case *ast.CallNode:
			v.logger.Infof("call node found: %+v", n)
		case *ast.BuiltinNode:
			v.logger.Infof("builtin node found: %+v", n)
		case *ast.ConditionalNode:
			v.logger.Infof("conditional node found: %+v", n)
		case *ast.ChainNode:
			v.logger.Infof("chain node found: %+v", n)
		case *ast.PairNode:
			v.logger.Infof("pair node found: %+v", n)
		case *ast.MapNode:
			v.logger.Infof("map node found: %+v", n)
		case *ast.SliceNode:
			v.logger.Infof("slice node found: %+v", n)
		case *ast.ClosureNode:
			v.logger.Infof("closure node found: %+v", n)
		case *ast.PointerNode:
			v.logger.Infof("pointer node found: %+v", n)
		default:
			v.logger.Infof("unknown node found: %+v | type: %T", n, n)*/
	}
}

/*
Build reconstruct all the variables used in a filter (to display their content later).
*/
func (v *visitor) Build(filter string, exprEnv ...expr.Option) (*ExprDebugger, error) {
	var expressions []*expression
	ret := &ExprDebugger{
		filter: filter,
	}
	if filter == "" {
		v.logger.Debugf("unable to create expr debugger with empty filter")
		return &ExprDebugger{}, nil
	}
	v.newVar = false
	v.vars = make(map[string][]string)
	tree, err := parser.Parse(filter)
	if err != nil {
		return nil, err
	}
	ast.Walk(&tree.Node, v)
	log.Debugf("vars: %+v", v.vars)

	for _, variable := range v.vars {
		if variable[0] != "evt" {
			continue
		}
		toBuild := strings.Join(variable, ".")
		v.logger.Debugf("compiling expression '%s'", toBuild)
		debugFilter, err := expr.Compile(toBuild, exprEnv...)
		if err != nil {
			return ret, fmt.Errorf("compilation of variable '%s' failed: %v", toBuild, err)
		}
		tmpExpression := &expression{
			toBuild,
			debugFilter,
		}
		expressions = append(expressions, tmpExpression)

	}
	ret.expression = expressions
	return ret, nil
}

// ExprDebugger contains the list of expression to be run when debugging an expression filter
type ExprDebugger struct {
	filter     string
	expression []*expression
}

// expression is the structure that represents the variable in string and compiled format
type expression struct {
	Str      string
	Compiled *vm.Program
}

/*
Run display the content of each variable of a filter by evaluating them with expr,
again the expr environment given in parameter
*/
func (e *ExprDebugger) Run(logger *logrus.Entry, filterResult bool, exprEnv map[string]interface{}) {
	if len(e.expression) == 0 {
		logger.Tracef("no variable to eval for filter '%s'", e.filter)
		return
	}
	logger.Debugf("eval(%s) = %s", e.filter, strings.ToUpper(strconv.FormatBool(filterResult)))
	logger.Debugf("eval variables:")
	for _, expression := range e.expression {
		debug, err := expr.Run(expression.Compiled, exprEnv)
		if err != nil {
			logger.Errorf("unable to print debug expression for '%s': %s", expression.Str, err)
		}
		logger.Debugf("       %s = '%v'", expression.Str, debug)
	}
}

// NewDebugger is the exported function that build the debuggers expressions
func NewDebugger(filter string, exprEnv ...expr.Option) (*ExprDebugger, error) {
	logger := log.WithField("component", "expr-debugger")
	visitor := &visitor{logger: logger}
	exprDebugger, err := visitor.Build(filter, exprEnv...)
	return exprDebugger, err
}
