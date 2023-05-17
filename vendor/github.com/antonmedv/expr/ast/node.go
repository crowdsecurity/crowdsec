package ast

import (
	"reflect"
	"regexp"

	"github.com/antonmedv/expr/builtin"
	"github.com/antonmedv/expr/file"
)

// Node represents items of abstract syntax tree.
type Node interface {
	Location() file.Location
	SetLocation(file.Location)
	Type() reflect.Type
	SetType(reflect.Type)
}

func Patch(node *Node, newNode Node) {
	newNode.SetType((*node).Type())
	newNode.SetLocation((*node).Location())
	*node = newNode
}

type base struct {
	loc      file.Location
	nodeType reflect.Type
}

func (n *base) Location() file.Location {
	return n.loc
}

func (n *base) SetLocation(loc file.Location) {
	n.loc = loc
}

func (n *base) Type() reflect.Type {
	return n.nodeType
}

func (n *base) SetType(t reflect.Type) {
	n.nodeType = t
}

type NilNode struct {
	base
}

type IdentifierNode struct {
	base
	Value       string
	Deref       bool
	FieldIndex  []int
	Method      bool // true if method, false if field
	MethodIndex int  // index of method, set only if Method is true
}

type IntegerNode struct {
	base
	Value int
}

type FloatNode struct {
	base
	Value float64
}

type BoolNode struct {
	base
	Value bool
}

type StringNode struct {
	base
	Value string
}

type ConstantNode struct {
	base
	Value interface{}
}

type UnaryNode struct {
	base
	Operator string
	Node     Node
}

type BinaryNode struct {
	base
	Regexp   *regexp.Regexp
	Operator string
	Left     Node
	Right    Node
}

type ChainNode struct {
	base
	Node Node
}

type MemberNode struct {
	base
	Node       Node
	Property   Node
	Name       string // Name of the filed or method. Used for error reporting.
	Optional   bool
	Deref      bool
	FieldIndex []int

	// TODO: Replace with a single MethodIndex field of &int type.
	Method      bool
	MethodIndex int
}

type SliceNode struct {
	base
	Node Node
	From Node
	To   Node
}

type CallNode struct {
	base
	Callee    Node
	Arguments []Node
	Typed     int
	Fast      bool
	Func      *builtin.Function
}

type BuiltinNode struct {
	base
	Name      string
	Arguments []Node
}

type ClosureNode struct {
	base
	Node Node
}

type PointerNode struct {
	base
}

type ConditionalNode struct {
	base
	Cond Node
	Exp1 Node
	Exp2 Node
}

type ArrayNode struct {
	base
	Nodes []Node
}

type MapNode struct {
	base
	Pairs []Node
}

type PairNode struct {
	base
	Key   Node
	Value Node
}
