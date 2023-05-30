package checker

import (
	"reflect"
	"time"

	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/conf"
)

var (
	nilType      = reflect.TypeOf(nil)
	boolType     = reflect.TypeOf(true)
	integerType  = reflect.TypeOf(0)
	floatType    = reflect.TypeOf(float64(0))
	stringType   = reflect.TypeOf("")
	arrayType    = reflect.TypeOf([]interface{}{})
	mapType      = reflect.TypeOf(map[string]interface{}{})
	anyType      = reflect.TypeOf(new(interface{})).Elem()
	timeType     = reflect.TypeOf(time.Time{})
	durationType = reflect.TypeOf(time.Duration(0))
	functionType = reflect.TypeOf(new(func(...interface{}) (interface{}, error))).Elem()
	errorType    = reflect.TypeOf((*error)(nil)).Elem()
)

func combined(a, b reflect.Type) reflect.Type {
	if a.Kind() == b.Kind() {
		return a
	}
	if isFloat(a) || isFloat(b) {
		return floatType
	}
	return integerType
}

func anyOf(t reflect.Type, fns ...func(reflect.Type) bool) bool {
	for _, fn := range fns {
		if fn(t) {
			return true
		}
	}
	return false
}

func or(l, r reflect.Type, fns ...func(reflect.Type) bool) bool {
	if isAny(l) && isAny(r) {
		return true
	}
	if isAny(l) && anyOf(r, fns...) {
		return true
	}
	if isAny(r) && anyOf(l, fns...) {
		return true
	}
	return false
}

func isAny(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Interface:
			return true
		}
	}
	return false
}

func isInteger(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			fallthrough
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return true
		}
	}
	return false
}

func isFloat(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Float32, reflect.Float64:
			return true
		}
	}
	return false
}

func isNumber(t reflect.Type) bool {
	return isInteger(t) || isFloat(t)
}

func isTime(t reflect.Type) bool {
	if t != nil {
		switch t {
		case timeType:
			return true
		}
	}
	return isAny(t)
}

func isDuration(t reflect.Type) bool {
	if t != nil {
		switch t {
		case durationType:
			return true
		}
	}
	return false
}

func isBool(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Bool:
			return true
		}
	}
	return false
}

func isString(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.String:
			return true
		}
	}
	return false
}

func isArray(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Ptr:
			return isArray(t.Elem())
		case reflect.Slice, reflect.Array:
			return true
		}
	}
	return false
}

func isMap(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Ptr:
			return isMap(t.Elem())
		case reflect.Map:
			return true
		}
	}
	return false
}

func isStruct(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Ptr:
			return isStruct(t.Elem())
		case reflect.Struct:
			return true
		}
	}
	return false
}

func isFunc(t reflect.Type) bool {
	if t != nil {
		switch t.Kind() {
		case reflect.Ptr:
			return isFunc(t.Elem())
		case reflect.Func:
			return true
		}
	}
	return false
}

func fetchField(t reflect.Type, name string) (reflect.StructField, bool) {
	if t != nil {
		// First check all structs fields.
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			// Search all fields, even embedded structs.
			if conf.FieldName(field) == name {
				return field, true
			}
		}

		// Second check fields of embedded structs.
		for i := 0; i < t.NumField(); i++ {
			anon := t.Field(i)
			if anon.Anonymous {
				if field, ok := fetchField(anon.Type, name); ok {
					field.Index = append(anon.Index, field.Index...)
					return field, true
				}
			}
		}
	}
	return reflect.StructField{}, false
}

func deref(t reflect.Type) (reflect.Type, bool) {
	if t == nil {
		return nil, false
	}
	if t.Kind() == reflect.Interface {
		return t, true
	}
	found := false
	for t != nil && t.Kind() == reflect.Ptr {
		e := t.Elem()
		switch e.Kind() {
		case reflect.Struct, reflect.Map, reflect.Array, reflect.Slice:
			return t, false
		default:
			found = true
			t = e
		}
	}
	return t, found
}

func isIntegerOrArithmeticOperation(node ast.Node) bool {
	switch n := node.(type) {
	case *ast.IntegerNode:
		return true
	case *ast.UnaryNode:
		switch n.Operator {
		case "+", "-":
			return true
		}
	case *ast.BinaryNode:
		switch n.Operator {
		case "+", "/", "-", "*":
			return true
		}
	}
	return false
}

func setTypeForIntegers(node ast.Node, t reflect.Type) {
	switch n := node.(type) {
	case *ast.IntegerNode:
		n.SetType(t)
	case *ast.UnaryNode:
		switch n.Operator {
		case "+", "-":
			setTypeForIntegers(n.Node, t)
		}
	case *ast.BinaryNode:
		switch n.Operator {
		case "+", "/", "-", "*":
			setTypeForIntegers(n.Left, t)
			setTypeForIntegers(n.Right, t)
		}
	}
}
