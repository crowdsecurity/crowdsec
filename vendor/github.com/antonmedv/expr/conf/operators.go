package conf

import (
	"reflect"

	"github.com/antonmedv/expr/ast"
)

// OperatorsTable maps binary operators to corresponding list of functions.
// Functions should be provided in the environment to allow operator overloading.
type OperatorsTable map[string][]string

func FindSuitableOperatorOverload(fns []string, types TypesTable, l, r reflect.Type) (reflect.Type, string, bool) {
	for _, fn := range fns {
		fnType := types[fn]
		firstInIndex := 0
		if fnType.Method {
			firstInIndex = 1 // As first argument to method is receiver.
		}
		firstArgType := fnType.Type.In(firstInIndex)
		secondArgType := fnType.Type.In(firstInIndex + 1)

		firstArgumentFit := l == firstArgType || (firstArgType.Kind() == reflect.Interface && (l == nil || l.Implements(firstArgType)))
		secondArgumentFit := r == secondArgType || (secondArgType.Kind() == reflect.Interface && (r == nil || r.Implements(secondArgType)))
		if firstArgumentFit && secondArgumentFit {
			return fnType.Type.Out(0), fn, true
		}
	}
	return nil, "", false
}

type OperatorPatcher struct {
	Operators OperatorsTable
	Types     TypesTable
}

func (p *OperatorPatcher) Visit(node *ast.Node) {
	binaryNode, ok := (*node).(*ast.BinaryNode)
	if !ok {
		return
	}

	fns, ok := p.Operators[binaryNode.Operator]
	if !ok {
		return
	}

	leftType := binaryNode.Left.Type()
	rightType := binaryNode.Right.Type()

	_, fn, ok := FindSuitableOperatorOverload(fns, p.Types, leftType, rightType)
	if ok {
		newNode := &ast.CallNode{
			Callee:    &ast.IdentifierNode{Value: fn},
			Arguments: []ast.Node{binaryNode.Left, binaryNode.Right},
		}
		ast.Patch(node, newNode)
	}
}
