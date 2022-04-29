package schemahcl

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"ariga.io/atlas/schema/schemaspec"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

var (
	// Marshal returns the Atlas HCL encoding of v.
	Marshal = schemaspec.MarshalerFunc(New().MarshalSpec)
)

var (
	// Unmarshal parses the Atlas HCL-encoded data and stores the result in the target.
	Unmarshal = schemaspec.UnmarshalerFunc(New().UnmarshalSpec)
)

type (
	container struct {
		Body hcl.Body `hcl:",remain"`
	}

	// state implements schemaspec.Unmarshaler and schemaspec.Marshaler for Atlas HCL syntax
	// and stores a configuration for these operations.
	state struct {
		config *Config
	}
)

// MarshalSpec implements schemaspec.Marshaler for Atlas HCL documents.
func (s *state) MarshalSpec(v interface{}) ([]byte, error) {
	r := &schemaspec.Resource{}
	if err := r.Scan(v); err != nil {
		return nil, fmt.Errorf("schemahcl: failed scanning %T to resource: %w", v, err)
	}
	return s.encode(r)
}

// UnmarshalSpec implements schemaspec.Unmarshaler.
func (s *state) UnmarshalSpec(data []byte, v interface{}) error {
	ctx := s.config.newCtx()
	spec, err := s.decode(ctx, data)
	if err != nil {
		return fmt.Errorf("schemahcl: failed decoding: %w", err)
	}
	if err := spec.As(v); err != nil {
		return fmt.Errorf("schemahcl: failed reading spec as %T: %w", v, err)
	}
	return nil
}

// decode decodes the input Atlas HCL document and returns a *schemaspec.Resource representing it.
func (s *state) decode(ctx *hcl.EvalContext, body []byte) (*schemaspec.Resource, error) {
	parser := hclparse.NewParser()
	srcHCL, diag := parser.ParseHCL(body, "")
	if diag.HasErrors() {
		return nil, diag
	}
	if srcHCL == nil {
		return nil, fmt.Errorf("schemahcl: no HCL syntax found in body")
	}
	c := &container{}
	ctx, err := evalCtx(ctx, srcHCL)
	if err != nil {
		return nil, err
	}
	if diag := gohcl.DecodeBody(srcHCL.Body, ctx, c); diag.HasErrors() {
		return nil, diag
	}
	return s.extract(ctx, c.Body)
}

func (s *state) extract(ctx *hcl.EvalContext, remain hcl.Body) (*schemaspec.Resource, error) {
	body, ok := remain.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("schemahcl: expected remainder to be of type *hclsyntax.Body")
	}
	attrs, err := s.toAttrs(ctx, body.Attributes, nil)
	if err != nil {
		return nil, err
	}
	res := &schemaspec.Resource{
		Attrs: attrs,
	}
	for _, blk := range body.Blocks {
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
func (s *state) mayExtendVars(ctx *hcl.EvalContext, scope []string) *hcl.EvalContext {
	vars, ok := s.config.pathVars[strings.Join(scope, ".")]
	if !ok {
		return ctx
	}
	ctx = ctx.NewChild()
	ctx.Variables = vars
	return ctx
}

func (s *state) toAttrs(ctx *hcl.EvalContext, hclAttrs hclsyntax.Attributes, scope []string) ([]*schemaspec.Attr, error) {
	var attrs []*schemaspec.Attr
	for _, hclAttr := range hclAttrs {
		ctx := s.mayExtendVars(ctx, append(scope, hclAttr.Name))
		at := &schemaspec.Attr{K: hclAttr.Name}
		value, diag := hclAttr.Expr.Value(ctx)
		if diag.HasErrors() {
			return nil, diag
		}
		var err error
		switch {
		case isRef(value):
			at.V = &schemaspec.Ref{V: value.GetAttr("__ref").AsString()}
		case value.Type() == ctyRawExpr:
			at.V = value.EncapsulatedValue().(*schemaspec.RawExpr)
		case value.Type() == ctyTypeSpec:
			at.V = value.EncapsulatedValue().(*schemaspec.Type)
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

func isRef(v cty.Value) bool {
	return v.Type().IsObjectType() && v.Type().HasAttribute("__ref")
}

func extractListValue(value cty.Value) (*schemaspec.ListValue, error) {
	lst := &schemaspec.ListValue{}
	it := value.ElementIterator()
	for it.Next() {
		_, v := it.Element()
		if isRef(v) {
			lst.V = append(lst.V, &schemaspec.Ref{V: v.GetAttr("__ref").AsString()})
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

func extractLiteralValue(value cty.Value) (*schemaspec.LiteralValue, error) {
	switch value.Type() {
	case ctySchemaLit:
		return value.EncapsulatedValue().(*schemaspec.LiteralValue), nil
	case cty.String:
		return &schemaspec.LiteralValue{V: strconv.Quote(value.AsString())}, nil
	case cty.Number:
		bf := value.AsBigFloat()
		num, _ := bf.Float64()
		return &schemaspec.LiteralValue{V: strconv.FormatFloat(num, 'f', -1, 64)}, nil
	case cty.Bool:
		return &schemaspec.LiteralValue{V: strconv.FormatBool(value.True())}, nil
	default:
		return nil, fmt.Errorf("schemahcl: unsupported type %q", value.Type().GoString())
	}
}

func (s *state) toResource(ctx *hcl.EvalContext, block *hclsyntax.Block, scope []string) (*schemaspec.Resource, error) {
	spec := &schemaspec.Resource{
		Type: block.Type,
	}
	if len(block.Labels) > 0 {
		spec.Name = block.Labels[0]
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

// encode encodes the give *schemaspec.Resource into a byte slice containing an Atlas HCL
// document representing it.
func (s *state) encode(r *schemaspec.Resource) ([]byte, error) {
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

func (s *state) writeResource(b *schemaspec.Resource, body *hclwrite.Body) error {
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

func labels(r *schemaspec.Resource) []string {
	var l []string
	if r.Name != "" {
		l = append(l, r.Name)
	}
	return l
}

func (s *state) writeAttr(attr *schemaspec.Attr, body *hclwrite.Body) error {
	attr = normalizeLiterals(attr)
	switch v := attr.V.(type) {
	case *schemaspec.Ref:
		expr := strings.ReplaceAll(v.V, "$", "")
		body.SetAttributeRaw(attr.K, hclRawTokens(expr))
	case *schemaspec.Type:
		if v.IsRef {
			expr := strings.ReplaceAll(v.T, "$", "")
			body.SetAttributeRaw(attr.K, hclRawTokens(expr))
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
	case *schemaspec.LiteralValue:
		body.SetAttributeRaw(attr.K, hclRawTokens(v.V))
	case *schemaspec.RawExpr:
		// TODO(rotemtam): the func name should be decided on contextual basis.
		fnc := fmt.Sprintf("sql(%q)", v.X)
		body.SetAttributeRaw(attr.K, hclRawTokens(fnc))
	case *schemaspec.ListValue:
		// Skip scanning nil slices ([]T(nil)) by default. Users that
		// want to print empty lists, should use make([]T, 0) instead.
		if v.V == nil {
			return nil
		}
		lst := make([]string, 0, len(v.V))
		for _, item := range v.V {
			switch v := item.(type) {
			case *schemaspec.Ref:
				expr := strings.ReplaceAll(v.V, "$", "")
				lst = append(lst, expr)
			case *schemaspec.LiteralValue:
				lst = append(lst, v.V)
			default:
				return fmt.Errorf("cannot write elem type %T of attr %q to HCL list", v, attr)
			}
		}
		body.SetAttributeRaw(attr.K, hclRawList(lst))
	default:
		return fmt.Errorf("schemacl: unknown literal type %T", v)
	}
	return nil
}

// normalizeLiterals transforms attriburtes with LiteralValue that cannot be
// written as correct HCL into RawExpr.
func normalizeLiterals(attr *schemaspec.Attr) *schemaspec.Attr {
	lv, ok := attr.V.(*schemaspec.LiteralValue)
	if !ok {
		return attr
	}
	exp := "x = " + lv.V
	p := hclparse.NewParser()
	if _, diag := p.ParseHCL([]byte(exp), ""); diag != nil {
		return &schemaspec.Attr{K: attr.K, V: &schemaspec.RawExpr{X: lv.V}}
	}
	return attr
}

func (s *state) findTypeSpec(t string) (*schemaspec.TypeSpec, bool) {
	for _, v := range s.config.types {
		if v.T == t {
			return v, true
		}
	}
	return nil, false
}

func hclType(spec *schemaspec.TypeSpec, typ *schemaspec.Type) (string, error) {
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
		case *schemaspec.LiteralValue:
			args = append(args, val.V)
		case *schemaspec.ListValue:
			for _, li := range val.V {
				lit, ok := li.(*schemaspec.LiteralValue)
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

func findAttr(attrs []*schemaspec.Attr, k string) (*schemaspec.Attr, bool) {
	for _, attr := range attrs {
		if attr.K == k {
			return attr, true
		}
	}
	return nil, false
}

func hclRawTokens(s string) hclwrite.Tokens {
	return hclwrite.Tokens{
		&hclwrite.Token{
			Type:  hclsyntax.TokenIdent,
			Bytes: []byte(s),
		},
	}
}

func hclRawList(items []string) hclwrite.Tokens {
	t := hclwrite.Tokens{&hclwrite.Token{
		Type:  hclsyntax.TokenOBrack,
		Bytes: []byte("["),
	}}
	for i, item := range items {
		if i > 0 {
			t = append(t, &hclwrite.Token{Type: hclsyntax.TokenComma, Bytes: []byte(",")})
		}
		t = append(t, &hclwrite.Token{Type: hclsyntax.TokenIdent, Bytes: []byte(item)})
	}
	t = append(t, &hclwrite.Token{
		Type:  hclsyntax.TokenCBrack,
		Bytes: []byte("]"),
	})
	return t
}
