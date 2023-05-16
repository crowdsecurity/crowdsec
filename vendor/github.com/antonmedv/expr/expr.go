package expr

import (
	"fmt"
	"reflect"

	"github.com/antonmedv/expr/ast"
	"github.com/antonmedv/expr/builtin"
	"github.com/antonmedv/expr/checker"
	"github.com/antonmedv/expr/compiler"
	"github.com/antonmedv/expr/conf"
	"github.com/antonmedv/expr/file"
	"github.com/antonmedv/expr/optimizer"
	"github.com/antonmedv/expr/parser"
	"github.com/antonmedv/expr/vm"
)

// Option for configuring config.
type Option func(c *conf.Config)

// Env specifies expected input of env for type checks.
// If struct is passed, all fields will be treated as variables,
// as well as all fields of embedded structs and struct itself.
// If map is passed, all items will be treated as variables.
// Methods defined on this type will be available as functions.
func Env(env interface{}) Option {
	return func(c *conf.Config) {
		c.WithEnv(env)
	}
}

// AllowUndefinedVariables allows to use undefined variables inside expressions.
// This can be used with expr.Env option to partially define a few variables.
func AllowUndefinedVariables() Option {
	return func(c *conf.Config) {
		c.Strict = false
	}
}

// Operator allows to replace a binary operator with a function.
func Operator(operator string, fn ...string) Option {
	return func(c *conf.Config) {
		c.Operator(operator, fn...)
	}
}

// ConstExpr defines func expression as constant. If all argument to this function is constants,
// then it can be replaced by result of this func call on compile step.
func ConstExpr(fn string) Option {
	return func(c *conf.Config) {
		c.ConstExpr(fn)
	}
}

// AsKind tells the compiler to expect kind of the result.
func AsKind(kind reflect.Kind) Option {
	return func(c *conf.Config) {
		c.Expect = kind
	}
}

// AsBool tells the compiler to expect a boolean result.
func AsBool() Option {
	return func(c *conf.Config) {
		c.Expect = reflect.Bool
	}
}

// AsInt tells the compiler to expect an int result.
func AsInt() Option {
	return func(c *conf.Config) {
		c.Expect = reflect.Int
	}
}

// AsInt64 tells the compiler to expect an int64 result.
func AsInt64() Option {
	return func(c *conf.Config) {
		c.Expect = reflect.Int64
	}
}

// AsFloat64 tells the compiler to expect a float64 result.
func AsFloat64() Option {
	return func(c *conf.Config) {
		c.Expect = reflect.Float64
	}
}

// Optimize turns optimizations on or off.
func Optimize(b bool) Option {
	return func(c *conf.Config) {
		c.Optimize = b
	}
}

// Patch adds visitor to list of visitors what will be applied before compiling AST to bytecode.
func Patch(visitor ast.Visitor) Option {
	return func(c *conf.Config) {
		c.Visitors = append(c.Visitors, visitor)
	}
}

// Function adds function to list of functions what will be available in expressions.
func Function(name string, fn func(params ...interface{}) (interface{}, error), types ...interface{}) Option {
	return func(c *conf.Config) {
		ts := make([]reflect.Type, len(types))
		for i, t := range types {
			t := reflect.TypeOf(t)
			if t.Kind() == reflect.Ptr {
				t = t.Elem()
			}
			if t.Kind() != reflect.Func {
				panic(fmt.Sprintf("expr: type of %s is not a function", name))
			}
			ts[i] = t
		}
		c.Functions[name] = &builtin.Function{
			Name:  name,
			Func:  fn,
			Types: ts,
		}
	}
}

// Compile parses and compiles given input expression to bytecode program.
func Compile(input string, ops ...Option) (*vm.Program, error) {
	config := conf.CreateNew()

	for _, op := range ops {
		op(config)
	}
	config.Check()

	if len(config.Operators) > 0 {
		config.Visitors = append(config.Visitors, &conf.OperatorPatcher{
			Operators: config.Operators,
			Types:     config.Types,
		})
	}

	tree, err := parser.Parse(input)
	if err != nil {
		return nil, err
	}

	if len(config.Visitors) > 0 {
		for _, v := range config.Visitors {
			// We need to perform types check, because some visitors may rely on
			// types information available in the tree.
			_, _ = checker.Check(tree, config)
			ast.Walk(&tree.Node, v)
		}
		_, err = checker.Check(tree, config)
		if err != nil {
			return nil, err
		}
	} else {
		_, err = checker.Check(tree, config)
		if err != nil {
			return nil, err
		}
	}

	if config.Optimize {
		err = optimizer.Optimize(&tree.Node, config)
		if err != nil {
			if fileError, ok := err.(*file.Error); ok {
				return nil, fileError.Bind(tree.Source)
			}
			return nil, err
		}
	}

	program, err := compiler.Compile(tree, config)
	if err != nil {
		return nil, err
	}

	return program, nil
}

// Run evaluates given bytecode program.
func Run(program *vm.Program, env interface{}) (interface{}, error) {
	return vm.Run(program, env)
}

// Eval parses, compiles and runs given input.
func Eval(input string, env interface{}) (interface{}, error) {
	if _, ok := env.(Option); ok {
		return nil, fmt.Errorf("misused expr.Eval: second argument (env) should be passed without expr.Env")
	}

	program, err := Compile(input)
	if err != nil {
		return nil, err
	}

	output, err := Run(program, env)
	if err != nil {
		return nil, err
	}

	return output, nil
}
