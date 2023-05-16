package builtin

import (
	"fmt"
	"reflect"
)

var (
	anyType     = reflect.TypeOf(new(interface{})).Elem()
	integerType = reflect.TypeOf(0)
	floatType   = reflect.TypeOf(float64(0))
)

type Function struct {
	Name     string
	Func     func(args ...interface{}) (interface{}, error)
	Opcode   int
	Types    []reflect.Type
	Validate func(args []reflect.Type) (reflect.Type, error)
}

const (
	Len = iota + 1
	Abs
	Int
	Float
)

var Builtins = map[int]*Function{
	Len: {
		Name:   "len",
		Opcode: Len,
		Validate: func(args []reflect.Type) (reflect.Type, error) {
			if len(args) != 1 {
				return anyType, fmt.Errorf("invalid number of arguments for len (expected 1, got %d)", len(args))
			}
			switch kind(args[0]) {
			case reflect.Array, reflect.Map, reflect.Slice, reflect.String, reflect.Interface:
				return integerType, nil
			}
			return anyType, fmt.Errorf("invalid argument for len (type %s)", args[0])
		},
	},
	Abs: {
		Name:   "abs",
		Opcode: Abs,
		Validate: func(args []reflect.Type) (reflect.Type, error) {
			if len(args) != 1 {
				return anyType, fmt.Errorf("invalid number of arguments for abs (expected 1, got %d)", len(args))
			}
			switch kind(args[0]) {
			case reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Interface:
				return args[0], nil
			}
			return anyType, fmt.Errorf("invalid argument for abs (type %s)", args[0])
		},
	},
	Int: {
		Name:   "int",
		Opcode: Int,
		Validate: func(args []reflect.Type) (reflect.Type, error) {
			if len(args) != 1 {
				return anyType, fmt.Errorf("invalid number of arguments for int (expected 1, got %d)", len(args))
			}
			switch kind(args[0]) {
			case reflect.Interface:
				return integerType, nil
			case reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				return integerType, nil
			case reflect.String:
				return integerType, nil
			}
			return anyType, fmt.Errorf("invalid argument for int (type %s)", args[0])
		},
	},
	Float: {
		Name:   "float",
		Opcode: Float,
		Validate: func(args []reflect.Type) (reflect.Type, error) {
			if len(args) != 1 {
				return anyType, fmt.Errorf("invalid number of arguments for float (expected 1, got %d)", len(args))
			}
			switch kind(args[0]) {
			case reflect.Interface:
				return floatType, nil
			case reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				return floatType, nil
			case reflect.String:
				return floatType, nil
			}
			return anyType, fmt.Errorf("invalid argument for float (type %s)", args[0])
		},
	},
}

func kind(t reflect.Type) reflect.Kind {
	if t == nil {
		return reflect.Invalid
	}
	return t.Kind()
}
