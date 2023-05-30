package compiler

import (
	"fmt"
	"reflect"

	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/conf"
	"github.com/antonmedv/expr/file"
	"github.com/antonmedv/expr/parser"
	. "github.com/antonmedv/expr/vm"
	"github.com/antonmedv/expr/vm/runtime"
)

const (
	placeholder = 12345
)

func Compile(tree *parser.Tree, config *conf.Config) (program *Program, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()

	c := &compiler{
		locations:      make([]file.Location, 0),
		constantsIndex: make(map[interface{}]int),
		functionsIndex: make(map[string]int),
	}

	if config != nil {
		c.mapEnv = config.MapEnv
		c.cast = config.Expect
	}

	c.compile(tree.Node)

	switch c.cast {
	case reflect.Int:
		c.emit(OpCast, 0)
	case reflect.Int64:
		c.emit(OpCast, 1)
	case reflect.Float64:
		c.emit(OpCast, 2)
	}

	program = &Program{
		Node:      tree.Node,
		Source:    tree.Source,
		Locations: c.locations,
		Constants: c.constants,
		Bytecode:  c.bytecode,
		Arguments: c.arguments,
		Functions: c.functions,
	}
	return
}

type compiler struct {
	locations      []file.Location
	bytecode       []Opcode
	constants      []interface{}
	constantsIndex map[interface{}]int
	functions      []Function
	functionsIndex map[string]int
	mapEnv         bool
	cast           reflect.Kind
	nodes          []ast.Node
	chains         [][]int
	arguments      []int
}

func (c *compiler) emitLocation(loc file.Location, op Opcode, arg int) int {
	c.bytecode = append(c.bytecode, op)
	current := len(c.bytecode)
	c.arguments = append(c.arguments, arg)
	c.locations = append(c.locations, loc)
	return current
}

func (c *compiler) emit(op Opcode, args ...int) int {
	arg := 0
	if len(args) > 1 {
		panic("too many arguments")
	}
	if len(args) == 1 {
		arg = args[0]
	}
	var loc file.Location
	if len(c.nodes) > 0 {
		loc = c.nodes[len(c.nodes)-1].Location()
	}
	return c.emitLocation(loc, op, arg)
}

func (c *compiler) emitPush(value interface{}) int {
	return c.emit(OpPush, c.addConstant(value))
}

func (c *compiler) addConstant(constant interface{}) int {
	indexable := true
	hash := constant
	switch reflect.TypeOf(constant).Kind() {
	case reflect.Slice, reflect.Map, reflect.Struct:
		indexable = false
	}
	if field, ok := constant.(*runtime.Field); ok {
		indexable = true
		hash = fmt.Sprintf("%v", field)
	}
	if method, ok := constant.(*runtime.Method); ok {
		indexable = true
		hash = fmt.Sprintf("%v", method)
	}
	if indexable {
		if p, ok := c.constantsIndex[hash]; ok {
			return p
		}
	}
	c.constants = append(c.constants, constant)
	p := len(c.constants) - 1
	if indexable {
		c.constantsIndex[hash] = p
	}
	return p
}

func (c *compiler) addFunction(node *ast.CallNode) int {
	if node.Func == nil {
		panic("function is nil")
	}
	if p, ok := c.functionsIndex[node.Func.Name]; ok {
		return p
	}
	p := len(c.functions)
	c.functions = append(c.functions, node.Func.Func)
	c.functionsIndex[node.Func.Name] = p
	return p
}

func (c *compiler) patchJump(placeholder int) {
	offset := len(c.bytecode) - placeholder
	c.arguments[placeholder-1] = offset
}

func (c *compiler) calcBackwardJump(to int) int {
	return len(c.bytecode) + 1 - to
}

func (c *compiler) compile(node ast.Node) {
	c.nodes = append(c.nodes, node)
	defer func() {
		c.nodes = c.nodes[:len(c.nodes)-1]
	}()

	switch n := node.(type) {
	case *ast.NilNode:
		c.NilNode(n)
	case *ast.IdentifierNode:
		c.IdentifierNode(n)
	case *ast.IntegerNode:
		c.IntegerNode(n)
	case *ast.FloatNode:
		c.FloatNode(n)
	case *ast.BoolNode:
		c.BoolNode(n)
	case *ast.StringNode:
		c.StringNode(n)
	case *ast.ConstantNode:
		c.ConstantNode(n)
	case *ast.UnaryNode:
		c.UnaryNode(n)
	case *ast.BinaryNode:
		c.BinaryNode(n)
	case *ast.ChainNode:
		c.ChainNode(n)
	case *ast.MemberNode:
		c.MemberNode(n)
	case *ast.SliceNode:
		c.SliceNode(n)
	case *ast.CallNode:
		c.CallNode(n)
	case *ast.BuiltinNode:
		c.BuiltinNode(n)
	case *ast.ClosureNode:
		c.ClosureNode(n)
	case *ast.PointerNode:
		c.PointerNode(n)
	case *ast.ConditionalNode:
		c.ConditionalNode(n)
	case *ast.ArrayNode:
		c.ArrayNode(n)
	case *ast.MapNode:
		c.MapNode(n)
	case *ast.PairNode:
		c.PairNode(n)
	default:
		panic(fmt.Sprintf("undefined node type (%T)", node))
	}
}

func (c *compiler) NilNode(_ *ast.NilNode) {
	c.emit(OpNil)
}

func (c *compiler) IdentifierNode(node *ast.IdentifierNode) {
	if c.mapEnv {
		c.emit(OpLoadFast, c.addConstant(node.Value))
	} else if len(node.FieldIndex) > 0 {
		c.emit(OpLoadField, c.addConstant(&runtime.Field{
			Index: node.FieldIndex,
			Path:  []string{node.Value},
		}))
	} else if node.Method {
		c.emit(OpLoadMethod, c.addConstant(&runtime.Method{
			Name:  node.Value,
			Index: node.MethodIndex,
		}))
	} else {
		c.emit(OpLoadConst, c.addConstant(node.Value))
	}
	if node.Deref {
		c.emit(OpDeref)
	} else if node.Type() == nil {
		c.emit(OpDeref)
	}
}

func (c *compiler) IntegerNode(node *ast.IntegerNode) {
	t := node.Type()
	if t == nil {
		c.emitPush(node.Value)
		return
	}
	switch t.Kind() {
	case reflect.Float32:
		c.emitPush(float32(node.Value))
	case reflect.Float64:
		c.emitPush(float64(node.Value))
	case reflect.Int:
		c.emitPush(node.Value)
	case reflect.Int8:
		c.emitPush(int8(node.Value))
	case reflect.Int16:
		c.emitPush(int16(node.Value))
	case reflect.Int32:
		c.emitPush(int32(node.Value))
	case reflect.Int64:
		c.emitPush(int64(node.Value))
	case reflect.Uint:
		c.emitPush(uint(node.Value))
	case reflect.Uint8:
		c.emitPush(uint8(node.Value))
	case reflect.Uint16:
		c.emitPush(uint16(node.Value))
	case reflect.Uint32:
		c.emitPush(uint32(node.Value))
	case reflect.Uint64:
		c.emitPush(uint64(node.Value))
	default:
		c.emitPush(node.Value)
	}
}

func (c *compiler) FloatNode(node *ast.FloatNode) {
	c.emitPush(node.Value)
}

func (c *compiler) BoolNode(node *ast.BoolNode) {
	if node.Value {
		c.emit(OpTrue)
	} else {
		c.emit(OpFalse)
	}
}

func (c *compiler) StringNode(node *ast.StringNode) {
	c.emitPush(node.Value)
}

func (c *compiler) ConstantNode(node *ast.ConstantNode) {
	c.emitPush(node.Value)
}

func (c *compiler) UnaryNode(node *ast.UnaryNode) {
	c.compile(node.Node)

	switch node.Operator {

	case "!", "not":
		c.emit(OpNot)

	case "+":
		// Do nothing

	case "-":
		c.emit(OpNegate)

	default:
		panic(fmt.Sprintf("unknown operator (%v)", node.Operator))
	}
}

func (c *compiler) BinaryNode(node *ast.BinaryNode) {
	l := kind(node.Left)
	r := kind(node.Right)

	switch node.Operator {
	case "==":
		c.compile(node.Left)
		c.compile(node.Right)

		if l == r && l == reflect.Int {
			c.emit(OpEqualInt)
		} else if l == r && l == reflect.String {
			c.emit(OpEqualString)
		} else {
			c.emit(OpEqual)
		}

	case "!=":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpEqual)
		c.emit(OpNot)

	case "or", "||":
		c.compile(node.Left)
		end := c.emit(OpJumpIfTrue, placeholder)
		c.emit(OpPop)
		c.compile(node.Right)
		c.patchJump(end)

	case "and", "&&":
		c.compile(node.Left)
		end := c.emit(OpJumpIfFalse, placeholder)
		c.emit(OpPop)
		c.compile(node.Right)
		c.patchJump(end)

	case "<":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpLess)

	case ">":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpMore)

	case "<=":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpLessOrEqual)

	case ">=":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpMoreOrEqual)

	case "+":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpAdd)

	case "-":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpSubtract)

	case "*":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpMultiply)

	case "/":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpDivide)

	case "%":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpModulo)

	case "**", "^":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpExponent)

	case "in":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpIn)

	case "matches":
		if node.Regexp != nil {
			c.compile(node.Left)
			c.emit(OpMatchesConst, c.addConstant(node.Regexp))
		} else {
			c.compile(node.Left)
			c.compile(node.Right)
			c.emit(OpMatches)
		}

	case "contains":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpContains)

	case "startsWith":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpStartsWith)

	case "endsWith":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpEndsWith)

	case "..":
		c.compile(node.Left)
		c.compile(node.Right)
		c.emit(OpRange)

	case "??":
		c.compile(node.Left)
		end := c.emit(OpJumpIfNotNil, placeholder)
		c.emit(OpPop)
		c.compile(node.Right)
		c.patchJump(end)

	default:
		panic(fmt.Sprintf("unknown operator (%v)", node.Operator))

	}
}

func (c *compiler) ChainNode(node *ast.ChainNode) {
	c.chains = append(c.chains, []int{})
	c.compile(node.Node)
	// Chain activate (got nit somewhere)
	for _, ph := range c.chains[len(c.chains)-1] {
		c.patchJump(ph)
	}
	c.chains = c.chains[:len(c.chains)-1]
}

func (c *compiler) MemberNode(node *ast.MemberNode) {
	if node.Method {
		c.compile(node.Node)
		c.emit(OpMethod, c.addConstant(&runtime.Method{
			Name:  node.Name,
			Index: node.MethodIndex,
		}))
		return
	}
	op := OpFetch
	original := node
	index := node.FieldIndex
	path := []string{node.Name}
	base := node.Node
	if len(node.FieldIndex) > 0 {
		op = OpFetchField
		for !node.Optional {
			ident, ok := base.(*ast.IdentifierNode)
			if ok && len(ident.FieldIndex) > 0 {
				if ident.Deref {
					panic("IdentifierNode should not be dereferenced")
				}
				index = append(ident.FieldIndex, index...)
				path = append([]string{ident.Value}, path...)
				c.emitLocation(ident.Location(), OpLoadField, c.addConstant(
					&runtime.Field{Index: index, Path: path},
				))
				goto deref
			}
			member, ok := base.(*ast.MemberNode)
			if ok && len(member.FieldIndex) > 0 {
				if member.Deref {
					panic("MemberNode should not be dereferenced")
				}
				index = append(member.FieldIndex, index...)
				path = append([]string{member.Name}, path...)
				node = member
				base = member.Node
			} else {
				break
			}
		}
	}

	c.compile(base)
	if node.Optional {
		ph := c.emit(OpJumpIfNil, placeholder)
		c.chains[len(c.chains)-1] = append(c.chains[len(c.chains)-1], ph)
	}

	if op == OpFetch {
		c.compile(node.Property)
		c.emit(OpFetch)
	} else {
		c.emitLocation(node.Location(), op, c.addConstant(
			&runtime.Field{Index: index, Path: path},
		))
	}

deref:
	if original.Deref {
		c.emit(OpDeref)
	} else if original.Type() == nil {
		c.emit(OpDeref)
	}
}

func (c *compiler) SliceNode(node *ast.SliceNode) {
	c.compile(node.Node)
	if node.To != nil {
		c.compile(node.To)
	} else {
		c.emit(OpLen)
	}
	if node.From != nil {
		c.compile(node.From)
	} else {
		c.emitPush(0)
	}
	c.emit(OpSlice)
}

func (c *compiler) CallNode(node *ast.CallNode) {
	for _, arg := range node.Arguments {
		c.compile(arg)
	}
	if node.Func != nil {
		if node.Func.Opcode > 0 {
			c.emit(OpBuiltin, node.Func.Opcode)
			return
		}
		switch len(node.Arguments) {
		case 0:
			c.emit(OpCall0, c.addFunction(node))
		case 1:
			c.emit(OpCall1, c.addFunction(node))
		case 2:
			c.emit(OpCall2, c.addFunction(node))
		case 3:
			c.emit(OpCall3, c.addFunction(node))
		default:
			c.emit(OpLoadFunc, c.addFunction(node))
			c.emit(OpCallN, len(node.Arguments))
		}
		return
	}
	c.compile(node.Callee)
	if node.Typed > 0 {
		c.emit(OpCallTyped, node.Typed)
		return
	} else if node.Fast {
		c.emit(OpCallFast, len(node.Arguments))
	} else {
		c.emit(OpCall, len(node.Arguments))
	}
}

func (c *compiler) BuiltinNode(node *ast.BuiltinNode) {
	switch node.Name {
	case "all":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		var loopBreak int
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			loopBreak = c.emit(OpJumpIfFalse, placeholder)
			c.emit(OpPop)
		})
		c.emit(OpTrue)
		c.patchJump(loopBreak)
		c.emit(OpEnd)

	case "none":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		var loopBreak int
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			c.emit(OpNot)
			loopBreak = c.emit(OpJumpIfFalse, placeholder)
			c.emit(OpPop)
		})
		c.emit(OpTrue)
		c.patchJump(loopBreak)
		c.emit(OpEnd)

	case "any":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		var loopBreak int
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			loopBreak = c.emit(OpJumpIfTrue, placeholder)
			c.emit(OpPop)
		})
		c.emit(OpFalse)
		c.patchJump(loopBreak)
		c.emit(OpEnd)

	case "one":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			c.emitCond(func() {
				c.emit(OpIncrementCount)
			})
		})
		c.emit(OpGetCount)
		c.emitPush(1)
		c.emit(OpEqual)
		c.emit(OpEnd)

	case "filter":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			c.emitCond(func() {
				c.emit(OpIncrementCount)
				c.emit(OpPointer)
			})
		})
		c.emit(OpGetCount)
		c.emit(OpEnd)
		c.emit(OpArray)

	case "map":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
		})
		c.emit(OpGetLen)
		c.emit(OpEnd)
		c.emit(OpArray)

	case "count":
		c.compile(node.Arguments[0])
		c.emit(OpBegin)
		c.emitLoop(func() {
			c.compile(node.Arguments[1])
			c.emitCond(func() {
				c.emit(OpIncrementCount)
			})
		})
		c.emit(OpGetCount)
		c.emit(OpEnd)

	default:
		panic(fmt.Sprintf("unknown builtin %v", node.Name))
	}
}

func (c *compiler) emitCond(body func()) {
	noop := c.emit(OpJumpIfFalse, placeholder)
	c.emit(OpPop)

	body()

	jmp := c.emit(OpJump, placeholder)
	c.patchJump(noop)
	c.emit(OpPop)
	c.patchJump(jmp)
}

func (c *compiler) emitLoop(body func()) {
	begin := len(c.bytecode)
	end := c.emit(OpJumpIfEnd, placeholder)

	body()

	c.emit(OpIncrementIt)
	c.emit(OpJumpBackward, c.calcBackwardJump(begin))
	c.patchJump(end)
}

func (c *compiler) ClosureNode(node *ast.ClosureNode) {
	c.compile(node.Node)
}

func (c *compiler) PointerNode(node *ast.PointerNode) {
	c.emit(OpPointer)
}

func (c *compiler) ConditionalNode(node *ast.ConditionalNode) {
	c.compile(node.Cond)
	otherwise := c.emit(OpJumpIfFalse, placeholder)

	c.emit(OpPop)
	c.compile(node.Exp1)
	end := c.emit(OpJump, placeholder)

	c.patchJump(otherwise)
	c.emit(OpPop)
	c.compile(node.Exp2)

	c.patchJump(end)
}

func (c *compiler) ArrayNode(node *ast.ArrayNode) {
	for _, node := range node.Nodes {
		c.compile(node)
	}

	c.emitPush(len(node.Nodes))
	c.emit(OpArray)
}

func (c *compiler) MapNode(node *ast.MapNode) {
	for _, pair := range node.Pairs {
		c.compile(pair)
	}

	c.emitPush(len(node.Pairs))
	c.emit(OpMap)
}

func (c *compiler) PairNode(node *ast.PairNode) {
	c.compile(node.Key)
	c.compile(node.Value)
}

func kind(node ast.Node) reflect.Kind {
	t := node.Type()
	if t == nil {
		return reflect.Invalid
	}
	return t.Kind()
}
