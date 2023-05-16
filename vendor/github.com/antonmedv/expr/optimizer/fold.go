package optimizer

import (
	"math"
	"reflect"

	. "github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/file"
)

type fold struct {
	applied bool
	err     *file.Error
}

func (fold *fold) Visit(node *Node) {
	patch := func(newNode Node) {
		fold.applied = true
		Patch(node, newNode)
	}
	// for IntegerNode the type may have been changed from int->float
	// preserve this information by setting the type after the Patch
	patchWithType := func(newNode Node, leafType reflect.Type) {
		patch(newNode)
		newNode.SetType(leafType)
	}

	switch n := (*node).(type) {
	case *UnaryNode:
		switch n.Operator {
		case "-":
			if i, ok := n.Node.(*IntegerNode); ok {
				patchWithType(&IntegerNode{Value: -i.Value}, n.Node.Type())
			}
			if i, ok := n.Node.(*FloatNode); ok {
				patchWithType(&FloatNode{Value: -i.Value}, n.Node.Type())
			}
		case "+":
			if i, ok := n.Node.(*IntegerNode); ok {
				patchWithType(&IntegerNode{Value: i.Value}, n.Node.Type())
			}
			if i, ok := n.Node.(*FloatNode); ok {
				patchWithType(&FloatNode{Value: i.Value}, n.Node.Type())
			}
		case "!", "not":
			if a := toBool(n.Node); a != nil {
				patch(&BoolNode{Value: !a.Value})
			}
		}

	case *BinaryNode:
		switch n.Operator {
		case "+":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&IntegerNode{Value: a.Value + b.Value}, a.Type())
				}
			}
			{
				a := toInteger(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: float64(a.Value) + b.Value}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value + float64(b.Value)}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value + b.Value}, a.Type())
				}
			}
			{
				a := toString(n.Left)
				b := toString(n.Right)
				if a != nil && b != nil {
					patch(&StringNode{Value: a.Value + b.Value})
				}
			}
		case "-":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&IntegerNode{Value: a.Value - b.Value}, a.Type())
				}
			}
			{
				a := toInteger(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: float64(a.Value) - b.Value}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value - float64(b.Value)}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value - b.Value}, a.Type())
				}
			}
		case "*":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&IntegerNode{Value: a.Value * b.Value}, a.Type())
				}
			}
			{
				a := toInteger(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: float64(a.Value) * b.Value}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value * float64(b.Value)}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value * b.Value}, a.Type())
				}
			}
		case "/":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: float64(a.Value) / float64(b.Value)}, a.Type())
				}
			}
			{
				a := toInteger(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: float64(a.Value) / b.Value}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value / float64(b.Value)}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: a.Value / b.Value}, a.Type())
				}
			}
		case "%":
			if a, ok := n.Left.(*IntegerNode); ok {
				if b, ok := n.Right.(*IntegerNode); ok {
					if b.Value == 0 {
						fold.err = &file.Error{
							Location: (*node).Location(),
							Message:  "integer divide by zero",
						}
						return
					}
					patch(&IntegerNode{Value: a.Value % b.Value})
				}
			}
		case "**", "^":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: math.Pow(float64(a.Value), float64(b.Value))}, a.Type())
				}
			}
			{
				a := toInteger(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: math.Pow(float64(a.Value), b.Value)}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: math.Pow(a.Value, float64(b.Value))}, a.Type())
				}
			}
			{
				a := toFloat(n.Left)
				b := toFloat(n.Right)
				if a != nil && b != nil {
					patchWithType(&FloatNode{Value: math.Pow(a.Value, b.Value)}, a.Type())
				}
			}
		case "and", "&&":
			a := toBool(n.Left)
			b := toBool(n.Right)

			if a != nil && a.Value { // true and x
				patch(n.Right)
			} else if b != nil && b.Value { // x and true
				patch(n.Left)
			} else if (a != nil && !a.Value) || (b != nil && !b.Value) { // "x and false" or "false and x"
				patch(&BoolNode{Value: false})
			}
		case "or", "||":
			a := toBool(n.Left)
			b := toBool(n.Right)

			if a != nil && !a.Value { // false or x
				patch(n.Right)
			} else if b != nil && !b.Value { // x or false
				patch(n.Left)
			} else if (a != nil && a.Value) || (b != nil && b.Value) { // "x or true" or "true or x"
				patch(&BoolNode{Value: true})
			}
		case "==":
			{
				a := toInteger(n.Left)
				b := toInteger(n.Right)
				if a != nil && b != nil {
					patch(&BoolNode{Value: a.Value == b.Value})
				}
			}
			{
				a := toString(n.Left)
				b := toString(n.Right)
				if a != nil && b != nil {
					patch(&BoolNode{Value: a.Value == b.Value})
				}
			}
			{
				a := toBool(n.Left)
				b := toBool(n.Right)
				if a != nil && b != nil {
					patch(&BoolNode{Value: a.Value == b.Value})
				}
			}
		}

	case *ArrayNode:
		if len(n.Nodes) > 0 {
			for _, a := range n.Nodes {
				switch a.(type) {
				case *IntegerNode, *FloatNode, *StringNode, *BoolNode:
					continue
				default:
					return
				}
			}
			value := make([]interface{}, len(n.Nodes))
			for i, a := range n.Nodes {
				switch b := a.(type) {
				case *IntegerNode:
					value[i] = b.Value
				case *FloatNode:
					value[i] = b.Value
				case *StringNode:
					value[i] = b.Value
				case *BoolNode:
					value[i] = b.Value
				}
			}
			patch(&ConstantNode{Value: value})
		}

	case *BuiltinNode:
		switch n.Name {
		case "filter":
			if len(n.Arguments) != 2 {
				return
			}
			if base, ok := n.Arguments[0].(*BuiltinNode); ok && base.Name == "filter" {
				patch(&BuiltinNode{
					Name: "filter",
					Arguments: []Node{
						base.Arguments[0],
						&BinaryNode{
							Operator: "&&",
							Left:     base.Arguments[1],
							Right:    n.Arguments[1],
						},
					},
				})
			}
		}
	}
}

func toString(n Node) *StringNode {
	switch a := n.(type) {
	case *StringNode:
		return a
	}
	return nil
}

func toInteger(n Node) *IntegerNode {
	switch a := n.(type) {
	case *IntegerNode:
		return a
	}
	return nil
}

func toFloat(n Node) *FloatNode {
	switch a := n.(type) {
	case *FloatNode:
		return a
	}
	return nil
}

func toBool(n Node) *BoolNode {
	switch a := n.(type) {
	case *BoolNode:
		return a
	}
	return nil
}
