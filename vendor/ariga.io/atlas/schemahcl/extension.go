// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schemahcl

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// Remainer is the interface that is implemented by types that can store
// additional attributes and children resources.
type Remainer interface {
	// Remain returns a resource representing any extra children and attributes
	// that are related to the struct but were not mapped to any of its fields.
	Remain() *Resource
}

// DefaultExtension can be embedded in structs that need basic default behavior.
// For instance, DefaultExtension implements Remainer, and has a private *Resource
// field that can store additional attributes and children that do not match the
// structs fields.
type DefaultExtension struct {
	Extra Resource
}

// Remain implements the Remainer interface.
func (d *DefaultExtension) Remain() *Resource {
	return &d.Extra
}

// Attr returns the Attr by the provided name and reports whether it was found.
func (d *DefaultExtension) Attr(name string) (*Attr, bool) {
	return d.Extra.Attr(name)
}

type registry map[string]any

var (
	extensions   = make(registry)
	extensionsMu sync.RWMutex
)

func (r registry) lookup(ext any) (string, bool) {
	extensionsMu.RLock()
	defer extensionsMu.RUnlock()
	for k, v := range r {
		if reflect.TypeOf(ext) == reflect.TypeOf(v) {
			return k, true
		}
	}
	return "", false
}

// implementers returns a slice of the names of the extensions that implement i.
func (r registry) implementers(i reflect.Type) ([]string, error) {
	if i.Kind() != reflect.Interface {
		return nil, fmt.Errorf("schemahcl: expected interface got %s", i.Kind())
	}
	var names []string
	for name, typ := range r {
		if reflect.TypeOf(typ).Implements(i) {
			names = append(names, name)
		}
	}
	return names, nil
}

// Register records the type of ext in the global extension registry.
// If Register is called twice with the same name or if ext is nil,
// it panics.
func Register(name string, ext any) {
	extensionsMu.Lock()
	defer extensionsMu.Unlock()
	if ext == nil {
		panic("schemahcl: Register extension is nil")
	}
	if _, dup := extensions[name]; dup {
		panic("schemahcl: Register called twice for type " + name)
	}
	extensions[name] = ext
}

// As reads the attributes and children resources of the resource into the target struct.
func (r *Resource) As(target any) error {
	if err := validateStructPtr(target); err != nil {
		return err
	}
	existingAttrs, existingChildren := existingElements(r)
	var seenName, seenQualifier bool
	v := reflect.ValueOf(target).Elem()
	for _, ft := range specFields(target) {
		field := v.FieldByName(ft.Name)
		switch {
		case ft.isName() && !hasAttr(r, ft.tag):
			if seenName {
				return errors.New("schemahcl: extension must have only one isName field")
			}
			seenName = true
			if field.Kind() != reflect.String {
				return errors.New("schemahcl: extension isName field must be of type string")
			}
			field.SetString(r.Name)
		case ft.isQualifier():
			if seenQualifier {
				return errors.New("schemahcl: extension must have only one qualifier field")
			}
			seenQualifier = true
			field.SetString(r.Qualifier)
		case hasAttr(r, ft.tag):
			attr, _ := r.Attr(ft.tag)
			if err := setField(field, attr); err != nil {
				return err
			}
			delete(existingAttrs, attr.K)
		case ft.isInterfaceSlice():
			elem := field.Type().Elem()
			impls, err := extensions.implementers(elem)
			if err != nil {
				return err
			}
			children := childrenOfType(r, impls...)
			slc := reflect.MakeSlice(reflect.SliceOf(elem), 0, len(children))
			for _, c := range children {
				typ, ok := extensions[c.Type]
				if !ok {
					return fmt.Errorf("extension %q not registered", c.Type)
				}
				n := reflect.New(reflect.TypeOf(typ).Elem())
				ext := n.Interface()
				if err := c.As(ext); err != nil {
					return err
				}
				slc = reflect.Append(slc, reflect.ValueOf(ext))
			}
			field.Set(slc)
			for _, i := range impls {
				delete(existingChildren, i)
			}
		case ft.isInterface():
			impls, err := extensions.implementers(ft.Type)
			if err != nil {
				return err
			}
			children := childrenOfType(r, impls...)
			if len(children) == 0 {
				continue
			}
			if len(children) > 1 {
				return fmt.Errorf("more than one blocks implement %q", ft.Type)
			}
			c := children[0]
			typ, ok := extensions[c.Type]
			if !ok {
				return fmt.Errorf("extension %q not registered", c.Type)
			}
			n := reflect.New(reflect.TypeOf(typ).Elem())
			ext := n.Interface()
			if err := c.As(ext); err != nil {
				return err
			}
			field.Set(n)
		case isResourceSlice(field.Type()):
			if err := setChildSlice(field, childrenOfType(r, ft.tag)); err != nil {
				return err
			}
			delete(existingChildren, ft.tag)
		case isSingleResource(field.Type()):
			c := childrenOfType(r, ft.tag)
			if len(c) == 0 {
				continue
			}
			res := c[0]
			n := reflect.New(field.Type().Elem())
			ext := n.Interface()
			if err := res.As(ext); err != nil {
				return err
			}
			field.Set(n)
			delete(existingChildren, ft.tag)
		}
	}
	rem, ok := target.(Remainer)
	if !ok {
		return nil
	}
	extras := rem.Remain()
	for attrName := range existingAttrs {
		attr, ok := r.Attr(attrName)
		if !ok {
			return fmt.Errorf("schemahcl: expected attr %q to exist", attrName)
		}
		extras.SetAttr(attr)
	}
	for childType := range existingChildren {
		children := childrenOfType(r, childType)
		extras.Children = append(extras.Children, children...)
	}
	return nil
}

// FinalName returns the final name for the resource by examining the struct tags for
// the extension of the Resource's type. If no such extension is registered or the
// extension struct does not have a name field, an error is returned.
func (r *Resource) FinalName() (string, error) {
	extensionsMu.RLock()
	defer extensionsMu.RUnlock()
	t, ok := extensions[r.Type]
	if !ok {
		return "", fmt.Errorf("no extension registered for %q", r.Type)
	}
	for _, fd := range specFields(t) {
		if fd.isName() {
			if fd.tag != "" {
				name, ok := r.Attr(fd.tag)
				if ok {
					return name.String()
				}
			}
			return r.Name, nil
		}
	}
	return "", fmt.Errorf("extension %q has no name field", r.Type)
}

func validateStructPtr(target any) error {
	typeOf := reflect.TypeOf(target)
	if typeOf.Kind() != reflect.Ptr {
		return errors.New("schemahcl: expected target to be a pointer")
	}
	if typeOf.Elem().Kind() != reflect.Struct {
		return errors.New("schemahcl: expected target to be a pointer to a struct")
	}
	return nil
}

func existingElements(r *Resource) (attrs, children map[string]struct{}) {
	attrs, children = make(map[string]struct{}), make(map[string]struct{})
	for _, ea := range r.Attrs {
		attrs[ea.K] = struct{}{}
	}
	for _, ec := range r.Children {
		children[ec.Type] = struct{}{}
	}
	return
}

func setChildSlice(field reflect.Value, children []*Resource) error {
	if field.Type().Kind() != reflect.Slice {
		return fmt.Errorf("schemahcl: expected field to be of kind slice")
	}
	if len(children) == 0 {
		return nil
	}
	typ := field.Type().Elem()
	slc := reflect.MakeSlice(reflect.SliceOf(typ), 0, len(children))
	for _, c := range children {
		n := reflect.New(typ.Elem())
		ext := n.Interface()
		if err := c.As(ext); err != nil {
			return err
		}
		slc = reflect.Append(slc, reflect.ValueOf(ext))
	}
	field.Set(slc)
	return nil
}

func setField(field reflect.Value, attr *Attr) error {
	switch field.Kind() {
	case reflect.Slice:
		return setSliceAttr(field, attr)
	case reflect.String:
		s, err := attr.String()
		if err != nil {
			return fmt.Errorf("schemahcl: value of attr %q cannot be read as string: %w", attr.K, err)
		}
		field.SetString(s)
	case reflect.Int, reflect.Int64:
		i, err := attr.Int()
		if err != nil {
			return fmt.Errorf("schemahcl: value of attr %q cannot be read as integer: %w", attr.K, err)
		}
		field.SetInt(int64(i))
	case reflect.Bool:
		b, err := attr.Bool()
		if err != nil {
			return fmt.Errorf("schemahcl: value of attr %q cannot be read as bool: %w", attr.K, err)
		}
		field.SetBool(b)
	case reflect.Ptr:
		if err := setPtr(field, attr.V); err != nil {
			return fmt.Errorf("schemahcl: failed setting pointer field %q: %w", attr.K, err)
		}
	case reflect.Interface:
		field.Set(reflect.ValueOf(attr.V))
	default:
		return fmt.Errorf("schemahcl: unsupported field kind %q", field.Kind())
	}
	return nil
}

func setPtr(field reflect.Value, val Value) error {
	rt := reflect.TypeOf(val)
	if field.Type() == rt {
		field.Set(reflect.ValueOf(val))
		return nil
	}
	// If we are setting a Type field handle RawExpr and Ref specifically.
	if _, ok := field.Interface().(*Type); ok {
		switch t := val.(type) {
		case *RawExpr:
			field.Set(reflect.ValueOf(&Type{T: t.X}))
			return nil
		case *Ref:
			field.Set(reflect.ValueOf(&Type{
				T:     t.V,
				IsRef: true,
			}))
			return nil
		}
	}
	if field.IsNil() {
		field.Set(reflect.New(field.Type().Elem()))
	}
	switch e := field.Interface().(type) {
	case *bool:
		b, err := BoolVal(val)
		if err != nil {
			return err
		}
		*e = b
	case *string:
		s, err := StrVal(val)
		if err != nil {
			return err
		}
		*e = s
	case *LiteralValue:
		s, err := StrVal(val)
		if err != nil {
			return err
		}
		e.V = s
	case *Ref:
		s, err := StrVal(val)
		if err != nil {
			return err
		}
		e.V = s
	default:
		return fmt.Errorf("unhandled pointer type %T", val)
	}
	return nil
}

// setSliceAttr sets the value of attr to the slice field. This function expects both the target field
// and the source attr to be slices.
func setSliceAttr(field reflect.Value, attr *Attr) error {
	lst, ok := attr.V.(*ListValue)
	if !ok {
		return fmt.Errorf("schemahcl: field is of type slice but attr %q does not contain a ListValue", attr.K)
	}
	typ := field.Type().Elem()

	slc := reflect.MakeSlice(reflect.SliceOf(typ), 0, len(lst.V))
	switch typ.Kind() {
	case reflect.String:
		s, err := attr.Strings()
		if err != nil {
			return fmt.Errorf("cannot read attribute %q as string list: %w", attr.K, err)
		}
		for _, item := range s {
			slc = reflect.Append(slc, reflect.ValueOf(item))
		}
	case reflect.Bool:
		bools, err := attr.Bools()
		if err != nil {
			return fmt.Errorf("cannot read attribute %q as bool list: %w", attr.K, err)
		}
		for _, item := range bools {
			slc = reflect.Append(slc, reflect.ValueOf(item))
		}
	case reflect.Ptr:
		if typ != reflect.TypeOf(&Ref{}) {
			return fmt.Errorf("only pointers to refs supported, got %s", typ)
		}
		for _, c := range lst.V {
			slc = reflect.Append(slc, reflect.ValueOf(c))
		}
	default:
		return fmt.Errorf("slice of unsupported kind: %q", typ.Kind())
	}
	field.Set(slc)
	return nil
}

// Scan reads the Extension into the Resource. Scan will override the Resource
// name or type if they are set for the extension.
func (r *Resource) Scan(ext any) error {
	if lookup, ok := extensions.lookup(ext); ok {
		r.Type = lookup
	}
	v := reflect.ValueOf(ext).Elem()
	for _, ft := range specFields(ext) {
		field := v.FieldByName(ft.Name)
		switch {
		case ft.omitempty() && isEmpty(field):
		case ft.isName():
			if field.Kind() != reflect.String {
				return errors.New("schemahcl: extension name field must be string")
			}
			r.Name = field.String()
		case ft.isQualifier():
			if field.Kind() != reflect.String {
				return errors.New("schemahcl: extension qualifer field must be string")
			}
			r.Qualifier = field.String()
		case isResourceSlice(field.Type()):
			for i := 0; i < field.Len(); i++ {
				ext := field.Index(i).Interface()
				child := &Resource{}
				if err := child.Scan(ext); err != nil {
					return err
				}
				child.Type = ft.tag
				r.Children = append(r.Children, child)
			}
		case isSingleResource(field.Type()):
			if field.IsNil() {
				continue
			}
			ext := field.Interface()
			child := &Resource{}
			if err := child.Scan(ext); err != nil {
				return err
			}
			child.Type = ft.tag
			r.Children = append(r.Children, child)
		case field.Kind() == reflect.Ptr:
			if field.IsNil() {
				continue
			}
			if err := scanPtr(ft.tag, r, field); err != nil {
				return err
			}
		default:
			if err := scanAttr(ft.tag, r, field); err != nil {
				return err
			}
		}
	}
	rem, ok := ext.(Remainer)
	if !ok {
		return nil
	}
	extra := rem.Remain()
	for _, attr := range extra.Attrs {
		r.SetAttr(attr)
	}
	r.Children = append(r.Children, extra.Children...)
	return nil
}

func scanPtr(key string, r *Resource, field reflect.Value) error {
	attr := &Attr{K: key}
	switch e := field.Interface().(type) {
	case *LiteralValue:
		attr.V = e
	case *Ref:
		attr.V = e
	case *Type:
		attr.V = e
	case *bool:
		attr.V = &LiteralValue{V: strconv.FormatBool(*e)}
	case *string:
		attr.V = &LiteralValue{V: strconv.Quote(*e)}
	default:
		return fmt.Errorf("schemahcl: unsupported pointer to %s", e)
	}
	r.SetAttr(attr)
	return nil
}

func scanAttr(key string, r *Resource, field reflect.Value) error {
	var lit string
	switch field.Kind() {
	case reflect.Slice:
		return scanSliceAttr(key, r, field)
	case reflect.String:
		lit = strconv.Quote(field.String())
	case reflect.Int:
		lit = fmt.Sprintf("%d", field.Int())
	case reflect.Bool:
		lit = strconv.FormatBool(field.Bool())
	case reflect.Interface:
		if field.IsNil() {
			return nil
		}
		i := field.Interface()
		v, ok := i.(Value)
		if !ok {
			return fmt.Errorf("schemahcl: unsupported interface type %T for field %q", i, key)
		}
		r.SetAttr(&Attr{
			K: key,
			V: v,
		})
		return nil
	default:
		return fmt.Errorf("schemahcl: unsupported field kind %q", field.Kind())
	}
	r.SetAttr(&Attr{
		K: key,
		V: &LiteralValue{V: lit},
	})
	return nil
}

// scanSliceAttr sets an Attr named "key" into the Resource r, by converting
// the value stored in "field" into a *ListValue.
func scanSliceAttr(key string, r *Resource, field reflect.Value) error {
	typ := field.Type()
	lst := &ListValue{}

	switch typ.Elem().Kind() {
	case reflect.String:
		for i := 0; i < field.Len(); i++ {
			item := field.Index(i).Interface().(string)
			lst.V = append(lst.V, &LiteralValue{V: strconv.Quote(item)})
		}
	case reflect.Bool:
		for i := 0; i < field.Len(); i++ {
			item := field.Index(i).Interface().(bool)
			lst.V = append(lst.V, &LiteralValue{V: strconv.FormatBool(item)})
		}
	case reflect.Ptr:
		if typ.Elem() != reflect.TypeOf(&Ref{}) {
			return fmt.Errorf("schemahcl: currently on ref slice values supported, got %s", typ)
		}
		for i := 0; i < field.Len(); i++ {
			item := field.Index(i).Interface().(*Ref)
			lst.V = append(lst.V, item)
		}
	default:
		return fmt.Errorf("unsupported kind %q for %q", typ.Kind(), key)
	}
	r.SetAttr(&Attr{
		K: key,
		V: lst,
	})
	return nil
}

// specFields uses reflection to find struct fields that are tagged with "spec"
// and returns a list of mappings from the tag to the field name.
func specFields(ext any) []fieldDesc {
	t := reflect.TypeOf(ext)
	var fields []fieldDesc
	for i := 0; i < t.Elem().NumField(); i++ {
		f := t.Elem().Field(i)
		tag, ok := f.Tag.Lookup("spec")
		if !ok {
			continue
		}
		d := fieldDesc{tag: tag, StructField: f}
		if idx := strings.IndexByte(tag, ','); idx != -1 {
			d.tag, d.options = tag[:idx], tag[idx+1:]
		}
		fields = append(fields, d)
	}
	return fields
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	}
	return false
}

type fieldDesc struct {
	tag     string // tag name.
	options string // rest of the options.
	reflect.StructField
}

func (f fieldDesc) isName() bool { return f.is("name") }

func (f fieldDesc) isQualifier() bool { return f.is("qualifier") }

func (f fieldDesc) omitempty() bool { return f.is("omitempty") }

func (f fieldDesc) is(t string) bool {
	for _, opt := range strings.Split(f.options, ",") {
		if opt == t {
			return true
		}
	}
	return false
}

func (f fieldDesc) isInterfaceSlice() bool {
	return f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Interface
}

func (f fieldDesc) isInterface() bool {
	return f.Type.Kind() == reflect.Interface
}

func childrenOfType(r *Resource, types ...string) []*Resource {
	var out []*Resource
	for _, c := range r.Children {
		for _, typ := range types {
			if c.Type == typ {
				out = append(out, c)
			}
		}
	}
	return out
}

func isSingleResource(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		return false
	}
	elem := t.Elem()
	if elem.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < elem.NumField(); i++ {
		f := elem.Field(i)
		if _, ok := f.Tag.Lookup("spec"); ok {
			return true
		}
		if f.Type == reflect.TypeOf(DefaultExtension{}) {
			return true
		}
	}
	return false
}

func isResourceSlice(t reflect.Type) bool {
	if t.Kind() != reflect.Slice {
		return false
	}
	return isSingleResource(t.Elem())
}

func hasAttr(r *Resource, name string) bool {
	_, ok := r.Attr(name)
	return ok
}
