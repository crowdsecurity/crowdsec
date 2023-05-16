// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schemahcl

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
)

type (
	// Config configures an unmarshaling.
	Config struct {
		types    []*TypeSpec
		newCtx   func() *hcl.EvalContext
		pathVars map[string]map[string]cty.Value
	}

	// Option configures a Config.
	Option func(*Config)
)

// New returns a State configured with options.
func New(opts ...Option) *State {
	cfg := &Config{
		pathVars: make(map[string]map[string]cty.Value),
		newCtx: func() *hcl.EvalContext {
			return &hcl.EvalContext{
				Variables: make(map[string]cty.Value),
				Functions: make(map[string]function.Function),
			}
		},
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return &State{config: cfg}
}

// WithScopedEnums configured a list of allowed ENUMs to be used in
// the given context, block or attribute. For example, the following
// option allows setting HASH or BTREE to the "using" attribute in
// "index" block.
//
//	WithScopedEnums("table.index.type", "HASH", "BTREE")
//
//	table "t" {
//		...
//		index "i" {
//			type = HASH     // Allowed.
//			type = INVALID  // Not Allowed.
//		}
//	}
//
//
func WithScopedEnums(path string, enums ...string) Option {
	return func(c *Config) {
		vars := make(map[string]cty.Value, len(enums))
		for i := range enums {
			vars[enums[i]] = cty.StringVal(enums[i])
		}
		c.pathVars[path] = vars
	}
}

// WithTypes configures the list of given types as identifiers in the unmarshaling context.
func WithTypes(typeSpecs []*TypeSpec) Option {
	newCtx := func() *hcl.EvalContext {
		ctx := &hcl.EvalContext{
			Variables: make(map[string]cty.Value),
			Functions: make(map[string]function.Function),
		}
		for _, ts := range typeSpecs {
			typeSpec := ts
			// If no required args exist, register the type as a variable in the HCL context.
			if len(typeFuncReqArgs(typeSpec)) == 0 {
				typ := &Type{T: typeSpec.T}
				ctx.Variables[typeSpec.Name] = cty.CapsuleVal(ctyTypeSpec, typ)
			}
			// If func args exist, register the type as a function in HCL.
			if len(typeFuncArgs(typeSpec)) > 0 {
				ctx.Functions[typeSpec.Name] = typeFuncSpec(typeSpec)
			}
		}
		ctx.Functions["sql"] = rawExprImpl()
		return ctx
	}
	return func(config *Config) {
		config.newCtx = newCtx
		config.types = append(config.types, typeSpecs...)
	}
}

func rawExprImpl() function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{
			{Name: "def", Type: cty.String, AllowNull: false},
		},
		Type: function.StaticReturnType(ctyRawExpr),
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			x := args[0].AsString()
			if len(x) == 0 {
				return cty.NilVal, errors.New("empty expression")
			}
			t := &RawExpr{X: x}
			return cty.CapsuleVal(ctyRawExpr, t), nil
		},
	})
}

// typeFuncSpec returns the HCL function for defining the type in the spec.
func typeFuncSpec(typeSpec *TypeSpec) function.Function {
	spec := &function.Spec{
		Type: function.StaticReturnType(ctyTypeSpec),
	}
	for _, arg := range typeFuncArgs(typeSpec) {
		if arg.Kind == reflect.Slice || !arg.Required {
			spec.VarParam = &function.Parameter{
				Name: "args",
				Type: cty.DynamicPseudoType,
			}
			continue
		}
		p := function.Parameter{
			Name:      arg.Name,
			AllowNull: !arg.Required,
		}
		switch arg.Kind {
		case reflect.String:
			p.Type = cty.String
		case reflect.Int, reflect.Float32, reflect.Int64:
			p.Type = cty.Number
		case reflect.Bool:
			p.Type = cty.Bool
		}
		spec.Params = append(spec.Params, p)
	}
	spec.Impl = typeFuncSpecImpl(spec, typeSpec)
	return function.New(spec)
}

// typeFuncSpecImpl returns the function implementation for the HCL function spec.
func typeFuncSpecImpl(_ *function.Spec, typeSpec *TypeSpec) function.ImplFunc {
	return func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		t := &Type{
			T: typeSpec.T,
		}
		if len(args) > len(typeSpec.Attributes) && typeSpec.Attributes[len(typeSpec.Attributes)-1].Kind != reflect.Slice {
			return cty.NilVal, fmt.Errorf("too many arguments for type definition %q", typeSpec.Name)
		}
		// TypeRegistry enforces that:
		// 1. Required attrs come before optionals
		// 2. Slice attrs can only be last
		for _, attr := range typeFuncArgs(typeSpec) {
			// If the attribute is a slice, read all remaining args into a list value.
			if attr.Kind == reflect.Slice {
				lst := &ListValue{}
				for _, arg := range args {
					v, err := extractLiteralValue(arg)
					if err != nil {
						return cty.NilVal, err
					}
					lst.V = append(lst.V, v)
				}
				t.Attrs = append(t.Attrs, &Attr{K: attr.Name, V: lst})
				break
			}
			if len(args) == 0 {
				break
			}
			// Pop the first arg and add it as a literal to the type.
			var arg cty.Value
			arg, args = args[0], args[1:]
			v, err := extractLiteralValue(arg)
			if err != nil {
				return cty.NilVal, err
			}
			t.Attrs = append(t.Attrs, &Attr{K: attr.Name, V: v})
		}
		return cty.CapsuleVal(ctyTypeSpec, t), nil
	}
}

// typeFuncArgs returns the type attributes that are configured via arguments to the
// type definition, for example precision and scale in a decimal definition, i.e `decimal(10,2)`.
func typeFuncArgs(spec *TypeSpec) []*TypeAttr {
	var args []*TypeAttr
	for _, attr := range spec.Attributes {
		// TODO(rotemtam): this should be defined on the TypeSpec.
		if attr.Name == "unsigned" {
			continue
		}
		args = append(args, attr)
	}
	return args
}

// typeFuncReqArgs returns the required type attributes that are configured via arguments.
// for instance, in MySQL a field may be defined as both `int` and `int(10)`, in this case
// it is not a required parameter.
func typeFuncReqArgs(spec *TypeSpec) []*TypeAttr {
	var args []*TypeAttr
	for _, arg := range typeFuncArgs(spec) {
		if arg.Required {
			args = append(args, arg)
		}
	}
	return args
}
