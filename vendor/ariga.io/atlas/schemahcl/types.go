// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schemahcl

import (
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/schema"

	"github.com/go-openapi/inflect"
)

// PrintType returns the string representation of a column type which can be parsed
// by the driver into a schema.Type.
func (r *TypeRegistry) PrintType(typ *Type) (string, error) {
	spec, ok := r.findT(typ.T)
	if !ok {
		return "", fmt.Errorf("specutil: type %q not found in registry", typ.T)
	}
	if len(spec.Attributes) == 0 {
		return typ.T, nil
	}
	var (
		args        []string
		mid, suffix string
	)
	for _, arg := range typ.Attrs {
		// TODO(rotemtam): make this part of the TypeSpec
		if arg.K == "unsigned" {
			b, err := arg.Bool()
			if err != nil {
				return "", err
			}
			if b {
				suffix += " unsigned"
			}
			continue
		}
		switch v := arg.V.(type) {
		case *LiteralValue:
			args = append(args, v.V)
		case *ListValue:
			for _, li := range v.V {
				lit, ok := li.(*LiteralValue)
				if !ok {
					return "", fmt.Errorf("expecting literal value. got: %T", li)
				}
				uq, err := strconv.Unquote(lit.V)
				if err != nil {
					return "", fmt.Errorf("expecting list items to be quoted strings: %w", err)
				}
				args = append(args, "'"+uq+"'")
			}
		default:
			return "", fmt.Errorf("unsupported type %T for PrintType", v)
		}
	}
	if len(args) > 0 {
		mid = "(" + strings.Join(args, ",") + ")"
	}
	return typ.T + mid + suffix, nil
}

// TypeRegistry is a collection of *schemahcl.TypeSpec.
type TypeRegistry struct {
	r      []*TypeSpec
	spec   func(schema.Type) (*Type, error)
	parser func(string) (schema.Type, error)
}

// WithFormatter configures the registry to use a formatting function for printing
// schema.Type as string.
func WithFormatter(f func(schema.Type) (string, error)) TypeRegistryOption {
	return func(registry *TypeRegistry) error {
		registry.spec = func(t schema.Type) (*Type, error) {
			s, err := f(t)
			if err != nil {
				return nil, fmt.Errorf("specutil: cannot format type %T: %w", t, err)
			}
			return &Type{T: s}, nil
		}
		return nil
	}
}

// WithSpecFunc configures the registry to use the given function for converting
// a schema.Type to schemahcl.Type
func WithSpecFunc(spec func(schema.Type) (*Type, error)) TypeRegistryOption {
	return func(registry *TypeRegistry) error {
		registry.spec = spec
		return nil
	}
}

// WithParser configures the registry to use a parsing function for converting
// a string to a schema.Type.
func WithParser(parser func(string) (schema.Type, error)) TypeRegistryOption {
	return func(registry *TypeRegistry) error {
		registry.parser = parser
		return nil
	}
}

// Register adds one or more TypeSpec to the registry.
func (r *TypeRegistry) Register(specs ...*TypeSpec) error {
	for _, s := range specs {
		if err := validSpec(s); err != nil {
			return fmt.Errorf("specutil: invalid typespec %q: %w", s.Name, err)
		}
		if _, exists := r.findT(s.T); exists {
			return fmt.Errorf("specutil: type with T of %q already registered", s.T)
		}
		if _, exists := r.findName(s.Name); exists {
			return fmt.Errorf("specutil: type with name of %q already registered", s.T)
		}
		r.r = append(r.r, s)
	}
	return nil
}

func validSpec(typeSpec *TypeSpec) error {
	var seenOptional bool
	for i, attr := range typeSpec.Attributes {
		if attr.Kind == reflect.Slice && i < len(typeSpec.Attributes)-1 {
			return fmt.Errorf("attr %q is of kind slice but not last", attr.Name)
		}
		if seenOptional && attr.Required {
			return fmt.Errorf("attr %q required after optional attr", attr.Name)
		}
		seenOptional = !attr.Required
	}
	return nil
}

// TypeRegistryOption configures a TypeRegistry.
type TypeRegistryOption func(*TypeRegistry) error

// WithSpecs configures the registry to register the given list of type specs.
func WithSpecs(specs ...*TypeSpec) TypeRegistryOption {
	return func(registry *TypeRegistry) error {
		if err := registry.Register(specs...); err != nil {
			return fmt.Errorf("failed registering types: %s", err)
		}
		return nil
	}
}

// NewRegistry creates a new *TypeRegistry, registers the provided types and panics
// if an error occurs.
func NewRegistry(opts ...TypeRegistryOption) *TypeRegistry {
	r := &TypeRegistry{}
	for _, opt := range opts {
		if err := opt(r); err != nil {
			log.Fatalf("failed configuring registry: %s", err)
		}
	}
	return r
}

// findName searches the registry for types that have the provided name.
func (r *TypeRegistry) findName(name string) (*TypeSpec, bool) {
	for _, current := range r.r {
		if current.Name == name {
			return current, true
		}
	}
	return nil, false
}

// findT searches the registry for types that have the provided T.
func (r *TypeRegistry) findT(t string) (*TypeSpec, bool) {
	for _, current := range r.r {
		if current.T == t {
			return current, true
		}
	}
	return nil, false
}

// Convert converts the schema.Type to a *schemahcl.Type.
func (r *TypeRegistry) Convert(typ schema.Type) (*Type, error) {
	if ut, ok := typ.(*schema.UnsupportedType); ok {
		return &Type{
			T: ut.T,
		}, nil
	}
	rv := reflect.ValueOf(typ)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if !rv.IsValid() {
		return nil, errors.New("specutil: invalid schema.Type on Convert")
	}
	typeSpec, ok := r.findType(rv)
	if !ok {
		return r.spec(typ)
	}
	if typeSpec.ToSpec != nil {
		return typeSpec.ToSpec(typ)
	}
	s := &Type{T: typeSpec.T}
	// Iterate the attributes in reverse order, so we can skip zero value and optional attrs.
	for i := len(typeSpec.Attributes) - 1; i >= 0; i-- {
		attr := typeSpec.Attributes[i]
		n := inflect.Camelize(attr.Name)
		field := rv.FieldByName(n)
		// If TypeSpec has an attribute that isn't mapped to a field on the schema.Type skip it.
		if !field.IsValid() || field.Kind() == reflect.Ptr && field.IsNil() {
			continue
		}
		if field = reflect.Indirect(field); field.Kind() != attr.Kind {
			return nil, errors.New("incompatible kinds on typespec attr and typefield")
		}
		switch attr.Kind {
		case reflect.Int, reflect.Int64:
			v := int(field.Int())
			if v == 0 && len(s.Attrs) == 0 {
				break
			}
			i := strconv.Itoa(v)
			s.Attrs = append([]*Attr{LitAttr(attr.Name, i)}, s.Attrs...)
		case reflect.Bool:
			v := field.Bool()
			if !v && len(s.Attrs) == 0 {
				break
			}
			b := strconv.FormatBool(v)
			s.Attrs = append([]*Attr{LitAttr(attr.Name, b)}, s.Attrs...)
		case reflect.Slice:
			lits := make([]string, 0, field.Len())
			for i := 0; i < field.Len(); i++ {
				fi := field.Index(i)
				if fi.Kind() != reflect.String {
					return nil, errors.New("specutil: only string slices currently supported")
				}
				lits = append(lits, strconv.Quote(fi.String()))
			}
			s.Attrs = append([]*Attr{ListAttr(attr.Name, lits...)}, s.Attrs...)
		default:
			return nil, fmt.Errorf("specutil: unsupported attr kind %s for attribute %q of %q", attr.Kind, attr.Name, typeSpec.Name)
		}
	}
	return s, nil
}

func (r *TypeRegistry) findType(rv reflect.Value) (*TypeSpec, bool) {
	tf := rv.FieldByName("T")
	if tf.IsValid() && tf.Kind() == reflect.String {
		name := tf.String()
		if typeSpec, ok := r.findT(name); ok {
			return typeSpec, true
		}
	}
	if typeSpec, ok := r.findRType(rv.Type()); ok {
		return typeSpec, true
	}
	return nil, false
}

func (r *TypeRegistry) findRType(rt reflect.Type) (*TypeSpec, bool) {
	for _, ts := range r.Specs() {
		if ts.RType != nil && ts.RType == rt {
			return ts, true
		}
	}
	return nil, false
}

// Specs returns the TypeSpecs in the registry.
func (r *TypeRegistry) Specs() []*TypeSpec {
	return r.r
}

// Type converts a *schemahcl.Type into a schema.Type.
func (r *TypeRegistry) Type(typ *Type, extra []*Attr) (schema.Type, error) {
	typeSpec, ok := r.findT(typ.T)
	if !ok {
		return r.parser(typ.T)
	}
	nfa := typeNonFuncArgs(typeSpec)
	picked := pickTypeAttrs(extra, nfa)
	cp := &Type{
		T: typ.T,
	}
	cp.Attrs = appendIfNotExist(typ.Attrs, picked)
	if typeSpec.FromSpec != nil {
		return typeSpec.FromSpec(cp)
	}
	printType, err := r.PrintType(cp)
	if err != nil {
		return nil, err
	}
	return r.parser(printType)
}

// TypeSpecOption configures a schemahcl.TypeSpec.
type TypeSpecOption func(*TypeSpec)

// WithAttributes returns an attributes TypeSpecOption.
func WithAttributes(attrs ...*TypeAttr) TypeSpecOption {
	return func(spec *TypeSpec) {
		spec.Attributes = attrs
	}
}

// WithTypeFormatter allows overriding the Format function for the Type.
func WithTypeFormatter(f func(*Type) (string, error)) TypeSpecOption {
	return func(spec *TypeSpec) {
		spec.Format = f
	}
}

// WithFromSpec allows configuring the FromSpec convert function using functional options.
func WithFromSpec(f func(*Type) (schema.Type, error)) TypeSpecOption {
	return func(spec *TypeSpec) {
		spec.FromSpec = f
	}
}

// WithToSpec allows configuring the ToSpec convert function using functional options.
func WithToSpec(f func(schema.Type) (*Type, error)) TypeSpecOption {
	return func(spec *TypeSpec) {
		spec.ToSpec = f
	}
}

// NewTypeSpec returns a TypeSpec with the provided name.
func NewTypeSpec(name string, opts ...TypeSpecOption) *TypeSpec {
	return AliasTypeSpec(name, name, opts...)
}

// AliasTypeSpec returns a TypeSpec with the provided name.
func AliasTypeSpec(name, dbType string, opts ...TypeSpecOption) *TypeSpec {
	ts := &TypeSpec{
		Name: name,
		T:    dbType,
	}
	for _, opt := range opts {
		opt(ts)
	}
	return ts
}

// SizeTypeAttr returns a TypeAttr for a size attribute.
func SizeTypeAttr(required bool) *TypeAttr {
	return &TypeAttr{
		Name:     "size",
		Kind:     reflect.Int,
		Required: required,
	}
}

// typeNonFuncArgs returns the type attributes that are NOT configured via arguments to the
// type definition, `int unsigned`.
func typeNonFuncArgs(spec *TypeSpec) []*TypeAttr {
	var args []*TypeAttr
	for _, attr := range spec.Attributes {
		// TODO(rotemtam): this should be defined on the TypeSpec.
		if attr.Name == "unsigned" {
			args = append(args, attr)
		}
	}
	return args
}

// pickTypeAttrs returns the relevant Attrs matching the wanted TypeAttrs.
func pickTypeAttrs(src []*Attr, wanted []*TypeAttr) []*Attr {
	keys := make(map[string]struct{})
	for _, w := range wanted {
		keys[w.Name] = struct{}{}
	}
	var picked []*Attr
	for _, attr := range src {
		if _, ok := keys[attr.K]; ok {
			picked = append(picked, attr)
		}
	}
	return picked
}

func appendIfNotExist(base []*Attr, additional []*Attr) []*Attr {
	exists := make(map[string]struct{})
	for _, attr := range base {
		exists[attr.K] = struct{}{}
	}
	for _, attr := range additional {
		if _, ok := exists[attr.K]; !ok {
			base = append(base, attr)
		}
	}
	return base
}
