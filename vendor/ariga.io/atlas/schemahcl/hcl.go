// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schemahcl

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// Marshal returns the Atlas HCL encoding of v.
var Marshal = MarshalerFunc(New().MarshalSpec)

type (
	// State is used to evaluate and marshal Atlas HCL documents and stores a configuration for these operations.
	State struct {
		config *Config
	}
	// Evaluator is the interface that wraps the Eval function.
	Evaluator interface {
		// Eval evaluates parsed HCL files using input variables into a schema.Realm.
		Eval(*hclparse.Parser, any, map[string]string) error
	}
	// EvalFunc is an adapter that allows the use of an ordinary function as an Evaluator.
	EvalFunc func(*hclparse.Parser, any, map[string]string) error
	// Marshaler is the interface that wraps the MarshalSpec function.
	Marshaler interface {
		// MarshalSpec marshals the provided input into a valid Atlas HCL document.
		MarshalSpec(any) ([]byte, error)
	}
	// MarshalerFunc is the function type that is implemented by the MarshalSpec
	// method of the Marshaler interface.
	MarshalerFunc func(any) ([]byte, error)
)

// MarshalSpec implements Marshaler for Atlas HCL documents.
func (s *State) MarshalSpec(v any) ([]byte, error) {
	r := &Resource{}
	if err := r.Scan(v); err != nil {
		return nil, fmt.Errorf("schemahcl: failed scanning %T to resource: %w", v, err)
	}
	return s.encode(r)
}

// EvalFiles evaluates the files in the provided paths using the input variables and
// populates v with the result.
func (s *State) EvalFiles(paths []string, v any, input map[string]string) error {
	parser := hclparse.NewParser()
	for _, path := range paths {
		if _, diag := parser.ParseHCLFile(path); diag.HasErrors() {
			return diag
		}
	}
	return s.Eval(parser, v, input)
}

// Eval evaluates the parsed HCL documents using the input variables and populates v
// using the result.
func (s *State) Eval(parsed *hclparse.Parser, v any, input map[string]string) error {
	ctx := s.config.newCtx()
	reg := &blockDef{
		fields:   make(map[string]struct{}),
		children: make(map[string]*blockDef),
	}
	files := parsed.Files()
	fileNames := make([]string, 0, len(files))
	allBlocks := make([]*hclsyntax.Block, 0, len(files))
	// Prepare reg and allBlocks.
	for name, file := range files {
		fileNames = append(fileNames, name)
		if err := s.setInputVals(ctx, file.Body, input); err != nil {
			return err
		}
		body := file.Body.(*hclsyntax.Body)
		for _, blk := range body.Blocks {
			// Variable definition blocks are available in the HCL source but not reachable by reference.
			if blk.Type == varBlock {
				continue
			}
			allBlocks = append(allBlocks, blk)
			reg.child(extractDef(blk, reg))
		}
	}
	vars, err := blockVars(allBlocks, "", reg)
	if err != nil {
		return err
	}
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]cty.Value)
	}
	for k, v := range vars {
		ctx.Variables[k] = v
	}
	spec := &Resource{}
	sort.Slice(fileNames, func(i, j int) bool {
		return fileNames[i] < fileNames[j]
	})
	for _, fn := range fileNames {
		file := files[fn]
		r, err := s.resource(ctx, file)
		if err != nil {
			return err
		}
		spec.Children = append(spec.Children, r.Children...)
		spec.Attrs = append(spec.Attrs, r.Attrs...)
	}
	if err := patchRefs(spec); err != nil {
		return err
	}
	if err := spec.As(v); err != nil {
		return fmt.Errorf("schemahcl: failed reading spec as %T: %w", v, err)
	}
	return nil
}

// EvalBytes evaluates the data byte-slice as an Atlas HCL document using the input variables
// and stores the result in v.
func (s *State) EvalBytes(data []byte, v any, input map[string]string) error {
	parser := hclparse.NewParser()
	if _, diag := parser.ParseHCL(data, ""); diag.HasErrors() {
		return diag
	}
	return s.Eval(parser, v, input)
}

// addrRef maps addresses to their referenced resource.
type addrRef map[string]*Resource

// patchRefs recursively searches for schemahcl.Ref under the provided schemahcl.Resource
// and patches any variables with their concrete names.
func patchRefs(spec *Resource) error {
	return make(addrRef).patch(spec)
}

func (r addrRef) patch(resource *Resource) error {
	cp := r.copy().load(resource, "")
	for _, attr := range resource.Attrs {
		if ref, ok := attr.V.(*Ref); ok {
			referenced, ok := cp[ref.V]
			if !ok {
				return fmt.Errorf("broken reference to %q", ref.V)
			}
			if name, err := referenced.FinalName(); err == nil {
				ref.V = strings.ReplaceAll(ref.V, referenced.Name, name)
			}
		}
	}
	for _, ch := range resource.Children {
		if err := cp.patch(ch); err != nil {
			return err
		}
	}
	return nil
}

func (r addrRef) copy() addrRef {
	n := make(addrRef)
	for k, v := range r {
		n[k] = v
	}
	return n
}

// load the references from the children of the resource.
func (r addrRef) load(res *Resource, track string) addrRef {
	unlabeled := 0
	for _, ch := range res.Children {
		current := rep(ch)
		if ch.Name == "" {
			current += strconv.Itoa(unlabeled)
			unlabeled++
		}
		if track != "" {
			current = track + "." + current
		}
		r[current] = ch
		r.load(ch, current)
	}
	return r
}

func rep(r *Resource) string {
	n := r.Name
	if r.Qualifier != "" {
		n = r.Qualifier + "." + n
	}
	return fmt.Sprintf("$%s.%s", r.Type, n)
}

// resource converts the hcl file to a schemahcl.Resource.
func (s *State) resource(ctx *hcl.EvalContext, file *hcl.File) (*Resource, error) {
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("schemahcl: expected remainder to be of type *hclsyntax.Body")
	}
	attrs, err := s.toAttrs(ctx, body.Attributes, nil)
	if err != nil {
		return nil, err
	}
	res := &Resource{
		Attrs: attrs,
	}
	for _, blk := range body.Blocks {
		// variable blocks may be included in the document but are skipped in unmarshaling.
		if blk.Type == varBlock {
			continue
		}
		ctx, err := setBlockVars(ctx.NewChild(), blk.Body)
		if err != nil {
			return nil, err
		}
		resource, err := s.toResource(ctx, blk, []string{blk.Type})
		if err != nil {
			return nil, err
		}
		res.Children = append(res.Children, resource)
	}
	return res, nil
}

// mayExtendVars gets the current scope context, and extend it with additional
// variables if it was configured this way using WithScopedEnums.
func (s *State) mayExtendVars(ctx *hcl.EvalContext, scope []string) *hcl.EvalContext {
	vars, ok := s.config.pathVars[strings.Join(scope, ".")]
	if !ok {
		return ctx
	}
	ctx = ctx.NewChild()
	ctx.Variables = vars
	return ctx
}

func (s *State) toAttrs(ctx *hcl.EvalContext, hclAttrs hclsyntax.Attributes, scope []string) ([]*Attr, error) {
	var attrs []*Attr
	for _, hclAttr := range hclAttrs {
		ctx := s.mayExtendVars(ctx, append(scope, hclAttr.Name))
		at := &Attr{K: hclAttr.Name}
		value, diag := hclAttr.Expr.Value(ctx)
		if diag.HasErrors() {
			return nil, s.typeError(diag)
		}
		var err error
		switch {
		case isRef(value):
			at.V = &Ref{V: value.GetAttr("__ref").AsString()}
		case value.Type() == ctyRawExpr:
			at.V = value.EncapsulatedValue().(*RawExpr)
		case value.Type() == ctyTypeSpec:
			at.V = value.EncapsulatedValue().(*Type)
		case value.Type().IsTupleType():
			at.V, err = extractListValue(value)
		default:
			at.V, err = extractLiteralValue(value)
		}
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, at)
	}
	// hclsyntax.Attrs is an alias for map[string]*Attribute
	sort.Slice(attrs, func(i, j int) bool {
		return attrs[i].K < attrs[j].K
	})
	return attrs, nil
}

// typeError improves diagnostic reporting in case of parse error.
func (s *State) typeError(diag hcl.Diagnostics) error {
	for _, d := range diag {
		switch e := d.Expression.(type) {
		case *hclsyntax.FunctionCallExpr:
			if d.Summary != "Call to unknown function" {
				continue
			}
			if t, ok := s.findTypeSpec(e.Name); ok && len(t.Attributes) == 0 {
				d.Detail = fmt.Sprintf("Type %q does not accept attributes", t.Name)
			}
		case *hclsyntax.ScopeTraversalExpr:
			if d.Summary != "Unknown variable" {
				continue
			}
			if t, ok := s.findTypeSpec(e.Traversal.RootName()); ok && len(t.Attributes) > 0 {
				d.Detail = fmt.Sprintf("Type %q requires at least 1 argument", t.Name)
			}
		}
	}
	return diag
}

func isRef(v cty.Value) bool {
	return v.Type().IsObjectType() && v.Type().HasAttribute("__ref")
}

func extractListValue(value cty.Value) (*ListValue, error) {
	lst := &ListValue{}
	it := value.ElementIterator()
	for it.Next() {
		_, v := it.Element()
		if isRef(v) {
			lst.V = append(lst.V, &Ref{V: v.GetAttr("__ref").AsString()})
			continue
		}
		litv, err := extractLiteralValue(v)
		if err != nil {
			return nil, err
		}
		lst.V = append(lst.V, litv)
	}
	return lst, nil
}

func extractLiteralValue(value cty.Value) (*LiteralValue, error) {
	switch value.Type() {
	case ctySchemaLit:
		return value.EncapsulatedValue().(*LiteralValue), nil
	case cty.String:
		return &LiteralValue{V: strconv.Quote(value.AsString())}, nil
	case cty.Number:
		bf := value.AsBigFloat()
		num, _ := bf.Float64()
		return &LiteralValue{V: strconv.FormatFloat(num, 'f', -1, 64)}, nil
	case cty.Bool:
		return &LiteralValue{V: strconv.FormatBool(value.True())}, nil
	default:
		return nil, fmt.Errorf("schemahcl: unsupported type %q", value.Type().GoString())
	}
}

func (s *State) toResource(ctx *hcl.EvalContext, block *hclsyntax.Block, scope []string) (*Resource, error) {
	spec := &Resource{
		Type: block.Type,
	}
	switch len(block.Labels) {
	case 0:
	case 1:
		spec.Name = block.Labels[0]
	case 2:
		spec.Qualifier = block.Labels[0]
		spec.Name = block.Labels[1]
	default:
		return nil, fmt.Errorf("too many labels for block: %s", block.Labels)
	}
	ctx = s.mayExtendVars(ctx, scope)
	attrs, err := s.toAttrs(ctx, block.Body.Attributes, scope)
	if err != nil {
		return nil, err
	}
	spec.Attrs = attrs
	for _, blk := range block.Body.Blocks {
		res, err := s.toResource(ctx, blk, append(scope, blk.Type))
		if err != nil {
			return nil, err
		}
		spec.Children = append(spec.Children, res)
	}
	return spec, nil
}

// encode encodes the give *schemahcl.Resource into a byte slice containing an Atlas HCL
// document representing it.
func (s *State) encode(r *Resource) ([]byte, error) {
	f := hclwrite.NewFile()
	body := f.Body()
	// If the resource has a Type then it is rendered as an HCL block.
	if r.Type != "" {
		blk := body.AppendNewBlock(r.Type, labels(r))
		body = blk.Body()
	}
	for _, attr := range r.Attrs {
		if err := s.writeAttr(attr, body); err != nil {
			return nil, err
		}
	}
	for _, res := range r.Children {
		if err := s.writeResource(res, body); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	_, err := f.WriteTo(&buf)
	return buf.Bytes(), err
}

func (s *State) writeResource(b *Resource, body *hclwrite.Body) error {
	blk := body.AppendNewBlock(b.Type, labels(b))
	nb := blk.Body()
	for _, attr := range b.Attrs {
		if err := s.writeAttr(attr, nb); err != nil {
			return err
		}
	}
	for _, b := range b.Children {
		if err := s.writeResource(b, nb); err != nil {
			return err
		}
	}
	return nil
}

func labels(r *Resource) []string {
	var l []string
	if r.Qualifier != "" {
		l = append(l, r.Qualifier)
	}
	if r.Name != "" {
		l = append(l, r.Name)
	}
	return l
}

func (s *State) writeAttr(attr *Attr, body *hclwrite.Body) error {
	attr = normalizeLiterals(attr)
	switch v := attr.V.(type) {
	case *Ref:
		body.SetAttributeRaw(attr.K, hclRefTokens(v.V))
	case *Type:
		if v.IsRef {
			body.SetAttributeRaw(attr.K, hclRefTokens(v.T))
			break
		}
		spec, ok := s.findTypeSpec(v.T)
		if !ok {
			v := fmt.Sprintf("sql(%q)", v.T)
			body.SetAttributeRaw(attr.K, hclRawTokens(v))
			break
		}
		st, err := hclType(spec, v)
		if err != nil {
			return err
		}
		body.SetAttributeRaw(attr.K, hclRawTokens(st))
	case *LiteralValue:
		body.SetAttributeRaw(attr.K, hclRawTokens(v.V))
	case *RawExpr:
		// TODO(rotemtam): the func name should be decided on contextual basis.
		fnc := fmt.Sprintf("sql(%q)", v.X)
		body.SetAttributeRaw(attr.K, hclRawTokens(fnc))
	case *ListValue:
		// Skip scanning nil slices ([]T(nil)) by default. Users that
		// want to print empty lists, should use make([]T, 0) instead.
		if v.V == nil {
			return nil
		}
		lst := make([]hclwrite.Tokens, 0, len(v.V))
		for _, item := range v.V {
			switch v := item.(type) {
			case *Ref:
				lst = append(lst, hclRefTokens(v.V))
			case *LiteralValue:
				lst = append(lst, hclRawTokens(v.V))
			default:
				return fmt.Errorf("cannot write elem type %T of attr %q to HCL list", v, attr)
			}
		}
		body.SetAttributeRaw(attr.K, hclList(lst))
	default:
		return fmt.Errorf("schemacl: unknown literal type %T", v)
	}
	return nil
}

// normalizeLiterals transforms attributes with LiteralValue that cannot be
// written as correct HCL into RawExpr.
func normalizeLiterals(attr *Attr) *Attr {
	lv, ok := attr.V.(*LiteralValue)
	if !ok {
		return attr
	}
	exp := "x = " + lv.V
	p := hclparse.NewParser()
	if _, diag := p.ParseHCL([]byte(exp), ""); diag != nil {
		return &Attr{K: attr.K, V: &RawExpr{X: lv.V}}
	}
	return attr
}

func (s *State) findTypeSpec(t string) (*TypeSpec, bool) {
	for _, v := range s.config.types {
		if v.T == t {
			return v, true
		}
	}
	return nil, false
}

func hclType(spec *TypeSpec, typ *Type) (string, error) {
	if spec.Format != nil {
		return spec.Format(typ)
	}
	if len(typeFuncArgs(spec)) == 0 {
		return spec.Name, nil
	}
	args := make([]string, 0, len(spec.Attributes))
	for _, param := range typeFuncArgs(spec) {
		arg, ok := findAttr(typ.Attrs, param.Name)
		if !ok {
			continue
		}
		switch val := arg.V.(type) {
		case *LiteralValue:
			args = append(args, val.V)
		case *ListValue:
			for _, li := range val.V {
				lit, ok := li.(*LiteralValue)
				if !ok {
					return "", errors.New("expecting literal value")
				}
				args = append(args, lit.V)
			}
		}
	}
	// If no args were chosen and the type can be described without a function.
	if len(args) == 0 && len(typeFuncReqArgs(spec)) == 0 {
		return spec.Name, nil
	}
	return fmt.Sprintf("%s(%s)", spec.Name, strings.Join(args, ",")), nil
}

func findAttr(attrs []*Attr, k string) (*Attr, bool) {
	for _, attr := range attrs {
		if attr.K == k {
			return attr, true
		}
	}
	return nil, false
}

func hclRefTokens(ref string) hclwrite.Tokens {
	var t []*hclwrite.Token
	for i, s := range strings.Split(ref, ".") {
		// Ignore the first $ as token for reference.
		if len(s) > 1 && s[0] == '$' {
			s = s[1:]
		}
		switch {
		case i == 0:
			t = append(t, hclRawTokens(s)...)
		case hclsyntax.ValidIdentifier(s):
			t = append(t, &hclwrite.Token{
				Type:  hclsyntax.TokenDot,
				Bytes: []byte{'.'},
			}, &hclwrite.Token{
				Type:  hclsyntax.TokenIdent,
				Bytes: []byte(s),
			})
		default:
			t = append(t, &hclwrite.Token{
				Type:  hclsyntax.TokenOBrack,
				Bytes: []byte{'['},
			})
			t = append(t, hclwrite.TokensForValue(cty.StringVal(s))...)
			t = append(t, &hclwrite.Token{
				Type:  hclsyntax.TokenCBrack,
				Bytes: []byte{']'},
			})
		}
	}
	return t
}

func hclRawTokens(s string) hclwrite.Tokens {
	return hclwrite.Tokens{
		&hclwrite.Token{
			Type:  hclsyntax.TokenIdent,
			Bytes: []byte(s),
		},
	}
}

func hclList(items []hclwrite.Tokens) hclwrite.Tokens {
	t := hclwrite.Tokens{&hclwrite.Token{
		Type:  hclsyntax.TokenOBrack,
		Bytes: []byte("["),
	}}
	for i, item := range items {
		if i > 0 {
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")})
		}
		t = append(t, item...)
	}
	t = append(t, &hclwrite.Token{
		Type:  hclsyntax.TokenCBrack,
		Bytes: []byte("]"),
	})
	return t
}

// Eval implements the Evaluator interface.
func (f EvalFunc) Eval(p *hclparse.Parser, i any, input map[string]string) error {
	return f(p, i, input)
}
