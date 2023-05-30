package checker

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/builtin"
	"github.com/antonmedv/expr/conf"
	"github.com/antonmedv/expr/file"
	"github.com/antonmedv/expr/parser"
	"github.com/antonmedv/expr/vm"
)

func Check(tree *parser.Tree, config *conf.Config) (t reflect.Type, err error) {
	if config == nil {
		config = conf.New(nil)
	}

	v := &visitor{
		config:      config,
		collections: make([]reflect.Type, 0),
		parents:     make([]ast.Node, 0),
	}

	t, _ = v.visit(tree.Node)

	if v.err != nil {
		return t, v.err.Bind(tree.Source)
	}

	if v.config.Expect != reflect.Invalid {
		switch v.config.Expect {
		case reflect.Int, reflect.Int64, reflect.Float64:
			if !isNumber(t) && !isAny(t) {
				return nil, fmt.Errorf("expected %v, but got %v", v.config.Expect, t)
			}
		default:
			if t != nil {
				if t.Kind() == v.config.Expect {
					return t, nil
				}
			}
			return nil, fmt.Errorf("expected %v, but got %v", v.config.Expect, t)
		}
	}

	return t, nil
}

type visitor struct {
	config      *conf.Config
	collections []reflect.Type
	parents     []ast.Node
	err         *file.Error
}

type info struct {
	method bool
	fn     *builtin.Function
}

func (v *visitor) visit(node ast.Node) (reflect.Type, info) {
	var t reflect.Type
	var i info
	v.parents = append(v.parents, node)
	switch n := node.(type) {
	case *ast.NilNode:
		t, i = v.NilNode(n)
	case *ast.IdentifierNode:
		t, i = v.IdentifierNode(n)
	case *ast.IntegerNode:
		t, i = v.IntegerNode(n)
	case *ast.FloatNode:
		t, i = v.FloatNode(n)
	case *ast.BoolNode:
		t, i = v.BoolNode(n)
	case *ast.StringNode:
		t, i = v.StringNode(n)
	case *ast.ConstantNode:
		t, i = v.ConstantNode(n)
	case *ast.UnaryNode:
		t, i = v.UnaryNode(n)
	case *ast.BinaryNode:
		t, i = v.BinaryNode(n)
	case *ast.ChainNode:
		t, i = v.ChainNode(n)
	case *ast.MemberNode:
		t, i = v.MemberNode(n)
	case *ast.SliceNode:
		t, i = v.SliceNode(n)
	case *ast.CallNode:
		t, i = v.CallNode(n)
	case *ast.BuiltinNode:
		t, i = v.BuiltinNode(n)
	case *ast.ClosureNode:
		t, i = v.ClosureNode(n)
	case *ast.PointerNode:
		t, i = v.PointerNode(n)
	case *ast.ConditionalNode:
		t, i = v.ConditionalNode(n)
	case *ast.ArrayNode:
		t, i = v.ArrayNode(n)
	case *ast.MapNode:
		t, i = v.MapNode(n)
	case *ast.PairNode:
		t, i = v.PairNode(n)
	default:
		panic(fmt.Sprintf("undefined node type (%T)", node))
	}
	v.parents = v.parents[:len(v.parents)-1]
	node.SetType(t)
	return t, i
}

func (v *visitor) error(node ast.Node, format string, args ...interface{}) (reflect.Type, info) {
	if v.err == nil { // show first error
		v.err = &file.Error{
			Location: node.Location(),
			Message:  fmt.Sprintf(format, args...),
		}
	}
	return anyType, info{} // interface represent undefined type
}

func (v *visitor) NilNode(*ast.NilNode) (reflect.Type, info) {
	return nilType, info{}
}

func (v *visitor) IdentifierNode(node *ast.IdentifierNode) (reflect.Type, info) {
	if fn, ok := v.config.Functions[node.Value]; ok {
		// Return anyType instead of func type as we don't know the arguments yet.
		// The func type can be one of the fn.Types. The type will be resolved
		// when the arguments are known in CallNode.
		return anyType, info{fn: fn}
	}
	if v.config.Types == nil {
		node.Deref = true
	} else if t, ok := v.config.Types[node.Value]; ok {
		if t.Ambiguous {
			return v.error(node, "ambiguous identifier %v", node.Value)
		}
		d, c := deref(t.Type)
		node.Deref = c
		node.Method = t.Method
		node.MethodIndex = t.MethodIndex
		node.FieldIndex = t.FieldIndex
		return d, info{method: t.Method}
	}
	if v.config.Strict {
		return v.error(node, "unknown name %v", node.Value)
	}
	if v.config.DefaultType != nil {
		return v.config.DefaultType, info{}
	}
	return anyType, info{}
}

func (v *visitor) IntegerNode(*ast.IntegerNode) (reflect.Type, info) {
	return integerType, info{}
}

func (v *visitor) FloatNode(*ast.FloatNode) (reflect.Type, info) {
	return floatType, info{}
}

func (v *visitor) BoolNode(*ast.BoolNode) (reflect.Type, info) {
	return boolType, info{}
}

func (v *visitor) StringNode(*ast.StringNode) (reflect.Type, info) {
	return stringType, info{}
}

func (v *visitor) ConstantNode(node *ast.ConstantNode) (reflect.Type, info) {
	return reflect.TypeOf(node.Value), info{}
}

func (v *visitor) UnaryNode(node *ast.UnaryNode) (reflect.Type, info) {
	t, _ := v.visit(node.Node)

	switch node.Operator {

	case "!", "not":
		if isBool(t) {
			return boolType, info{}
		}
		if isAny(t) {
			return boolType, info{}
		}

	case "+", "-":
		if isNumber(t) {
			return t, info{}
		}
		if isAny(t) {
			return anyType, info{}
		}

	default:
		return v.error(node, "unknown operator (%v)", node.Operator)
	}

	return v.error(node, `invalid operation: %v (mismatched type %v)`, node.Operator, t)
}

func (v *visitor) BinaryNode(node *ast.BinaryNode) (reflect.Type, info) {
	l, _ := v.visit(node.Left)
	r, _ := v.visit(node.Right)

	// check operator overloading
	if fns, ok := v.config.Operators[node.Operator]; ok {
		t, _, ok := conf.FindSuitableOperatorOverload(fns, v.config.Types, l, r)
		if ok {
			return t, info{}
		}
	}

	switch node.Operator {
	case "==", "!=":
		if isNumber(l) && isNumber(r) {
			return boolType, info{}
		}
		if l == nil || r == nil { // It is possible to compare with nil.
			return boolType, info{}
		}
		if l.Kind() == r.Kind() {
			return boolType, info{}
		}
		if isAny(l) || isAny(r) {
			return boolType, info{}
		}

	case "or", "||", "and", "&&":
		if isBool(l) && isBool(r) {
			return boolType, info{}
		}
		if or(l, r, isBool) {
			return boolType, info{}
		}

	case "<", ">", ">=", "<=":
		if isNumber(l) && isNumber(r) {
			return boolType, info{}
		}
		if isString(l) && isString(r) {
			return boolType, info{}
		}
		if isTime(l) && isTime(r) {
			return boolType, info{}
		}
		if or(l, r, isNumber, isString, isTime) {
			return boolType, info{}
		}

	case "-":
		if isNumber(l) && isNumber(r) {
			return combined(l, r), info{}
		}
		if isTime(l) && isTime(r) {
			return durationType, info{}
		}
		if or(l, r, isNumber, isTime) {
			return anyType, info{}
		}

	case "/", "*":
		if isNumber(l) && isNumber(r) {
			return combined(l, r), info{}
		}
		if or(l, r, isNumber) {
			return anyType, info{}
		}

	case "**", "^":
		if isNumber(l) && isNumber(r) {
			return floatType, info{}
		}
		if or(l, r, isNumber) {
			return floatType, info{}
		}

	case "%":
		if isInteger(l) && isInteger(r) {
			return combined(l, r), info{}
		}
		if or(l, r, isInteger) {
			return anyType, info{}
		}

	case "+":
		if isNumber(l) && isNumber(r) {
			return combined(l, r), info{}
		}
		if isString(l) && isString(r) {
			return stringType, info{}
		}
		if isTime(l) && isDuration(r) {
			return timeType, info{}
		}
		if isDuration(l) && isTime(r) {
			return timeType, info{}
		}
		if or(l, r, isNumber, isString, isTime, isDuration) {
			return anyType, info{}
		}

	case "in":
		if (isString(l) || isAny(l)) && isStruct(r) {
			return boolType, info{}
		}
		if isMap(r) {
			return boolType, info{}
		}
		if isArray(r) {
			return boolType, info{}
		}
		if isAny(l) && anyOf(r, isString, isArray, isMap) {
			return boolType, info{}
		}
		if isAny(r) {
			return boolType, info{}
		}

	case "matches":
		if s, ok := node.Right.(*ast.StringNode); ok {
			r, err := regexp.Compile(s.Value)
			if err != nil {
				return v.error(node, err.Error())
			}
			node.Regexp = r
		}
		if isString(l) && isString(r) {
			return boolType, info{}
		}
		if or(l, r, isString) {
			return boolType, info{}
		}

	case "contains", "startsWith", "endsWith":
		if isString(l) && isString(r) {
			return boolType, info{}
		}
		if or(l, r, isString) {
			return boolType, info{}
		}

	case "..":
		ret := reflect.SliceOf(integerType)
		if isInteger(l) && isInteger(r) {
			return ret, info{}
		}
		if or(l, r, isInteger) {
			return ret, info{}
		}

	case "??":
		if l == nil && r != nil {
			return r, info{}
		}
		if l != nil && r == nil {
			return l, info{}
		}
		if l == nil && r == nil {
			return nilType, info{}
		}
		if r.AssignableTo(l) {
			return l, info{}
		}
		return anyType, info{}

	default:
		return v.error(node, "unknown operator (%v)", node.Operator)

	}

	return v.error(node, `invalid operation: %v (mismatched types %v and %v)`, node.Operator, l, r)
}

func (v *visitor) ChainNode(node *ast.ChainNode) (reflect.Type, info) {
	return v.visit(node.Node)
}

func (v *visitor) MemberNode(node *ast.MemberNode) (reflect.Type, info) {
	base, _ := v.visit(node.Node)
	prop, _ := v.visit(node.Property)

	if name, ok := node.Property.(*ast.StringNode); ok {
		if base == nil {
			return v.error(node, "type %v has no field %v", base, name.Value)
		}
		// First, check methods defined on base type itself,
		// independent of which type it is. Without dereferencing.
		if m, ok := base.MethodByName(name.Value); ok {
			if base.Kind() == reflect.Interface {
				// In case of interface type method will not have a receiver,
				// and to prevent checker decreasing numbers of in arguments
				// return method type as not method (second argument is false).

				// Also, we can not use m.Index here, because it will be
				// different indexes for different types which implement
				// the same interface.
				return m.Type, info{}
			} else {
				node.Method = true
				node.MethodIndex = m.Index
				node.Name = name.Value
				return m.Type, info{method: true}
			}
		}
	}

	if base.Kind() == reflect.Ptr {
		base = base.Elem()
	}

	switch base.Kind() {
	case reflect.Interface:
		node.Deref = true
		return anyType, info{}

	case reflect.Map:
		if prop != nil && !prop.AssignableTo(base.Key()) && !isAny(prop) {
			return v.error(node.Property, "cannot use %v to get an element from %v", prop, base)
		}
		t, c := deref(base.Elem())
		node.Deref = c
		return t, info{}

	case reflect.Array, reflect.Slice:
		if !isInteger(prop) && !isAny(prop) {
			return v.error(node.Property, "array elements can only be selected using an integer (got %v)", prop)
		}
		t, c := deref(base.Elem())
		node.Deref = c
		return t, info{}

	case reflect.Struct:
		if name, ok := node.Property.(*ast.StringNode); ok {
			propertyName := name.Value
			if field, ok := fetchField(base, propertyName); ok {
				t, c := deref(field.Type)
				node.Deref = c
				node.FieldIndex = field.Index
				node.Name = propertyName
				return t, info{}
			}
			if len(v.parents) > 1 {
				if _, ok := v.parents[len(v.parents)-2].(*ast.CallNode); ok {
					return v.error(node, "type %v has no method %v", base, propertyName)
				}
			}
			return v.error(node, "type %v has no field %v", base, propertyName)
		}
	}

	return v.error(node, "type %v[%v] is undefined", base, prop)
}

func (v *visitor) SliceNode(node *ast.SliceNode) (reflect.Type, info) {
	t, _ := v.visit(node.Node)

	switch t.Kind() {
	case reflect.Interface:
		// ok
	case reflect.String, reflect.Array, reflect.Slice:
		// ok
	default:
		return v.error(node, "cannot slice %v", t)
	}

	if node.From != nil {
		from, _ := v.visit(node.From)
		if !isInteger(from) && !isAny(from) {
			return v.error(node.From, "non-integer slice index %v", from)
		}
	}
	if node.To != nil {
		to, _ := v.visit(node.To)
		if !isInteger(to) && !isAny(to) {
			return v.error(node.To, "non-integer slice index %v", to)
		}
	}
	return t, info{}
}

func (v *visitor) CallNode(node *ast.CallNode) (reflect.Type, info) {
	fn, fnInfo := v.visit(node.Callee)

	if fnInfo.fn != nil {
		f := fnInfo.fn
		node.Func = f
		if f.Validate != nil {
			args := make([]reflect.Type, len(node.Arguments))
			for i, arg := range node.Arguments {
				args[i], _ = v.visit(arg)
			}
			t, err := f.Validate(args)
			if err != nil {
				return v.error(node, "%v", err)
			}
			return t, info{}
		}
		if len(f.Types) == 0 {
			t, err := v.checkFunc(f.Name, functionType, false, node)
			if err != nil {
				if v.err == nil {
					v.err = err
				}
				return anyType, info{}
			}
			// No type was specified, so we assume the function returns any.
			return t, info{}
		}
		var lastErr *file.Error
		for _, t := range f.Types {
			outType, err := v.checkFunc(f.Name, t, false, node)
			if err != nil {
				lastErr = err
				continue
			}
			return outType, info{}
		}
		if lastErr != nil {
			if v.err == nil {
				v.err = lastErr
			}
			return anyType, info{}
		}
	}

	fnName := "function"
	if identifier, ok := node.Callee.(*ast.IdentifierNode); ok {
		fnName = identifier.Value
	}
	if member, ok := node.Callee.(*ast.MemberNode); ok {
		if name, ok := member.Property.(*ast.StringNode); ok {
			fnName = name.Value
		}
	}
	switch fn.Kind() {
	case reflect.Interface:
		return anyType, info{}
	case reflect.Func:
		inputParamsCount := 1 // for functions
		if fnInfo.method {
			inputParamsCount = 2 // for methods
		}
		// TODO: Deprecate OpCallFast and move fn(...any) any to TypedFunc list.
		// To do this we need add support for variadic arguments in OpCallTyped.
		if !isAny(fn) &&
			fn.IsVariadic() &&
			fn.NumIn() == inputParamsCount &&
			fn.NumOut() == 1 &&
			fn.Out(0).Kind() == reflect.Interface {
			rest := fn.In(fn.NumIn() - 1) // function has only one param for functions and two for methods
			if rest.Kind() == reflect.Slice && rest.Elem().Kind() == reflect.Interface {
				node.Fast = true
			}
		}

		outType, err := v.checkFunc(fnName, fn, fnInfo.method, node)
		if err != nil {
			if v.err == nil {
				v.err = err
			}
			return anyType, info{}
		}

		v.findTypedFunc(node, fn, fnInfo.method)

		return outType, info{}
	}
	return v.error(node, "%v is not callable", fn)
}

func (v *visitor) checkFunc(name string, fn reflect.Type, method bool, node *ast.CallNode) (reflect.Type, *file.Error) {
	if isAny(fn) {
		return anyType, nil
	}

	if fn.NumOut() == 0 {
		return anyType, &file.Error{
			Location: node.Location(),
			Message:  fmt.Sprintf("func %v doesn't return value", name),
		}
	}
	if numOut := fn.NumOut(); numOut > 2 {
		return anyType, &file.Error{
			Location: node.Location(),
			Message:  fmt.Sprintf("func %v returns more then two values", name),
		}
	}

	// If func is method on an env, first argument should be a receiver,
	// and actual arguments less than fnNumIn by one.
	fnNumIn := fn.NumIn()
	if method {
		fnNumIn--
	}
	// Skip first argument in case of the receiver.
	fnInOffset := 0
	if method {
		fnInOffset = 1
	}

	if fn.IsVariadic() {
		if len(node.Arguments) < fnNumIn-1 {
			return anyType, &file.Error{
				Location: node.Location(),
				Message:  fmt.Sprintf("not enough arguments to call %v", name),
			}
		}
	} else {
		if len(node.Arguments) > fnNumIn {
			return anyType, &file.Error{
				Location: node.Location(),
				Message:  fmt.Sprintf("too many arguments to call %v", name),
			}
		}
		if len(node.Arguments) < fnNumIn {
			return anyType, &file.Error{
				Location: node.Location(),
				Message:  fmt.Sprintf("not enough arguments to call %v", name),
			}
		}
	}

	for i, arg := range node.Arguments {
		t, _ := v.visit(arg)

		var in reflect.Type
		if fn.IsVariadic() && i >= fnNumIn-1 {
			// For variadic arguments fn(xs ...int), go replaces type of xs (int) with ([]int).
			// As we compare arguments one by one, we need underling type.
			in = fn.In(fn.NumIn() - 1).Elem()
		} else {
			in = fn.In(i + fnInOffset)
		}

		if isIntegerOrArithmeticOperation(arg) && (isInteger(in) || isFloat(in)) {
			t = in
			setTypeForIntegers(arg, t)
		}

		if t == nil {
			continue
		}

		if !t.AssignableTo(in) && t.Kind() != reflect.Interface {
			return anyType, &file.Error{
				Location: arg.Location(),
				Message:  fmt.Sprintf("cannot use %v as argument (type %v) to call %v ", t, in, name),
			}
		}
	}

	return fn.Out(0), nil
}

func (v *visitor) BuiltinNode(node *ast.BuiltinNode) (reflect.Type, info) {
	switch node.Name {
	case "all", "none", "any", "one":
		collection, _ := v.visit(node.Arguments[0])
		if !isArray(collection) && !isAny(collection) {
			return v.error(node.Arguments[0], "builtin %v takes only array (got %v)", node.Name, collection)
		}

		v.collections = append(v.collections, collection)
		closure, _ := v.visit(node.Arguments[1])
		v.collections = v.collections[:len(v.collections)-1]

		if isFunc(closure) &&
			closure.NumOut() == 1 &&
			closure.NumIn() == 1 && isAny(closure.In(0)) {

			if !isBool(closure.Out(0)) && !isAny(closure.Out(0)) {
				return v.error(node.Arguments[1], "closure should return boolean (got %v)", closure.Out(0).String())
			}
			return boolType, info{}
		}
		return v.error(node.Arguments[1], "closure should has one input and one output param")

	case "filter":
		collection, _ := v.visit(node.Arguments[0])
		if !isArray(collection) && !isAny(collection) {
			return v.error(node.Arguments[0], "builtin %v takes only array (got %v)", node.Name, collection)
		}

		v.collections = append(v.collections, collection)
		closure, _ := v.visit(node.Arguments[1])
		v.collections = v.collections[:len(v.collections)-1]

		if isFunc(closure) &&
			closure.NumOut() == 1 &&
			closure.NumIn() == 1 && isAny(closure.In(0)) {

			if !isBool(closure.Out(0)) && !isAny(closure.Out(0)) {
				return v.error(node.Arguments[1], "closure should return boolean (got %v)", closure.Out(0).String())
			}
			if isAny(collection) {
				return arrayType, info{}
			}
			return reflect.SliceOf(collection.Elem()), info{}
		}
		return v.error(node.Arguments[1], "closure should has one input and one output param")

	case "map":
		collection, _ := v.visit(node.Arguments[0])
		if !isArray(collection) && !isAny(collection) {
			return v.error(node.Arguments[0], "builtin %v takes only array (got %v)", node.Name, collection)
		}

		v.collections = append(v.collections, collection)
		closure, _ := v.visit(node.Arguments[1])
		v.collections = v.collections[:len(v.collections)-1]

		if isFunc(closure) &&
			closure.NumOut() == 1 &&
			closure.NumIn() == 1 && isAny(closure.In(0)) {

			return reflect.SliceOf(closure.Out(0)), info{}
		}
		return v.error(node.Arguments[1], "closure should has one input and one output param")

	case "count":
		collection, _ := v.visit(node.Arguments[0])
		if !isArray(collection) && !isAny(collection) {
			return v.error(node.Arguments[0], "builtin %v takes only array (got %v)", node.Name, collection)
		}

		v.collections = append(v.collections, collection)
		closure, _ := v.visit(node.Arguments[1])
		v.collections = v.collections[:len(v.collections)-1]

		if isFunc(closure) &&
			closure.NumOut() == 1 &&
			closure.NumIn() == 1 && isAny(closure.In(0)) {
			if !isBool(closure.Out(0)) && !isAny(closure.Out(0)) {
				return v.error(node.Arguments[1], "closure should return boolean (got %v)", closure.Out(0).String())
			}

			return integerType, info{}
		}
		return v.error(node.Arguments[1], "closure should has one input and one output param")

	default:
		return v.error(node, "unknown builtin %v", node.Name)
	}
}

func (v *visitor) ClosureNode(node *ast.ClosureNode) (reflect.Type, info) {
	t, _ := v.visit(node.Node)
	return reflect.FuncOf([]reflect.Type{anyType}, []reflect.Type{t}, false), info{}
}

func (v *visitor) PointerNode(node *ast.PointerNode) (reflect.Type, info) {
	if len(v.collections) == 0 {
		return v.error(node, "cannot use pointer accessor outside closure")
	}

	collection := v.collections[len(v.collections)-1]
	switch collection.Kind() {
	case reflect.Interface:
		return anyType, info{}
	case reflect.Array, reflect.Slice:
		return collection.Elem(), info{}
	}
	return v.error(node, "cannot use %v as array", collection)
}

func (v *visitor) ConditionalNode(node *ast.ConditionalNode) (reflect.Type, info) {
	c, _ := v.visit(node.Cond)
	if !isBool(c) && !isAny(c) {
		return v.error(node.Cond, "non-bool expression (type %v) used as condition", c)
	}

	t1, _ := v.visit(node.Exp1)
	t2, _ := v.visit(node.Exp2)

	if t1 == nil && t2 != nil {
		return t2, info{}
	}
	if t1 != nil && t2 == nil {
		return t1, info{}
	}
	if t1 == nil && t2 == nil {
		return nilType, info{}
	}
	if t1.AssignableTo(t2) {
		return t1, info{}
	}
	return anyType, info{}
}

func (v *visitor) ArrayNode(node *ast.ArrayNode) (reflect.Type, info) {
	for _, node := range node.Nodes {
		v.visit(node)
	}
	return arrayType, info{}
}

func (v *visitor) MapNode(node *ast.MapNode) (reflect.Type, info) {
	for _, pair := range node.Pairs {
		v.visit(pair)
	}
	return mapType, info{}
}

func (v *visitor) PairNode(node *ast.PairNode) (reflect.Type, info) {
	v.visit(node.Key)
	v.visit(node.Value)
	return nilType, info{}
}

func (v *visitor) findTypedFunc(node *ast.CallNode, fn reflect.Type, method bool) {
	// OnCallTyped doesn't work for functions with variadic arguments,
	// and doesn't work named function, like `type MyFunc func() int`.
	// In PkgPath() is an empty string, it's unnamed function.
	if !fn.IsVariadic() && fn.PkgPath() == "" {
		fnNumIn := fn.NumIn()
		fnInOffset := 0
		if method {
			fnNumIn--
			fnInOffset = 1
		}
	funcTypes:
		for i := range vm.FuncTypes {
			if i == 0 {
				continue
			}
			typed := reflect.ValueOf(vm.FuncTypes[i]).Elem().Type()
			if typed.Kind() != reflect.Func {
				continue
			}
			if typed.NumOut() != fn.NumOut() {
				continue
			}
			for j := 0; j < typed.NumOut(); j++ {
				if typed.Out(j) != fn.Out(j) {
					continue funcTypes
				}
			}
			if typed.NumIn() != fnNumIn {
				continue
			}
			for j := 0; j < typed.NumIn(); j++ {
				if typed.In(j) != fn.In(j+fnInOffset) {
					continue funcTypes
				}
			}
			node.Typed = i
		}
	}
}
