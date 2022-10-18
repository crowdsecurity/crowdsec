package exprhelpers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/antonmedv/expr/parser"
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
	newVar     bool
	currentID  string
	properties []string
	vars       []string
}

/*
Enter should be present for the interface but is never used
*/
func (v *visitor) Enter(node *ast.Node) {}

/*
Exit is called when running ast.Walk(node, visitor), each time a node exit.
So we have the node information and we can get the identifier (first level of the struct)
and its properties to reconstruct the complete variable.
*/
func (v *visitor) Exit(node *ast.Node) {
	if n, ok := (*node).(*ast.IdentifierNode); ok {
		if !v.newVar {
			v.newVar = true
			v.currentID = n.Value
		} else {
			fullVar := fmt.Sprintf("%s.%s", v.currentID, strings.Join(v.properties, "."))
			v.vars = append(v.vars, fullVar)
			v.properties = []string{}
			v.currentID = n.Value
		}
	} else if n, ok := (*node).(*ast.PropertyNode); ok {
		v.properties = append(v.properties, n.Property)
	}
}

/*
Build reconstruct all the variables used in a filter (to display their content later).
*/
func (v *visitor) Build(filter string, exprEnv expr.Option) (*ExprDebugger, error) {
	var expressions []*expression
	ret := &ExprDebugger{
		filter: filter,
	}
	if filter == "" {
		log.Debugf("unable to create expr debugger with empty filter")
		return &ExprDebugger{}, nil
	}
	v.newVar = false
	tree, err := parser.Parse(filter)
	if err != nil {
		return nil, err
	}
	ast.Walk(&tree.Node, v)
	if v.currentID != "" && len(v.properties) > 0 { // if its a variable with property (eg. evt.Line.Labels)
		fullVar := fmt.Sprintf("%s.%s", v.currentID, strings.Join(v.properties, "."))
		v.vars = append(v.vars, fullVar)
	} else if v.currentID != "" && len(v.properties) == 0 { // if it's a variable without property
		fullVar := v.currentID
		v.vars = append(v.vars, fullVar)
	} else {
		log.Debugf("no variable in filter : '%s'", filter)
	}
	v.properties = []string{}
	v.currentID = ""
	for _, variable := range v.vars {
		debugFilter, err := expr.Compile(variable, exprEnv)
		if err != nil {
			return ret, fmt.Errorf("compilation of variable '%s' failed: %v", variable, err)
		}
		tmpExpression := &expression{
			variable,
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
func NewDebugger(filter string, exprEnv expr.Option) (*ExprDebugger, error) {
	visitor := &visitor{}
	exprDebugger, err := visitor.Build(filter, exprEnv)
	return exprDebugger, err
}
