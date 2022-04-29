package schemahcl

import (
	"fmt"
	"reflect"
	"strconv"

	"ariga.io/atlas/schema/schemaspec"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// evalCtx constructs an *hcl.EvalContext with the Variables field populated with per
// block type reference maps that can be used in the HCL file evaluation. For example,
// if the evaluated file contains blocks such as:
//	greeting "english" {
//		word = "hello"
//	}
//	greeting "hebrew" {
//		word = "shalom"
//	}
//
// They can be then referenced in other blocks:
//	message "welcome_hebrew" {
//		title = "{greeting.hebrew.word}, world!"
//	}
//
func evalCtx(ctx *hcl.EvalContext, f *hcl.File) (*hcl.EvalContext, error) {
	c := &container{}
	if diag := gohcl.DecodeBody(f.Body, ctx, c); diag.HasErrors() {
		return nil, diag
	}
	b, ok := c.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("schemahcl: expected an hcl body")
	}
	return setBlockVars(ctx, b)
}

func setBlockVars(ctx *hcl.EvalContext, b *hclsyntax.Body) (*hcl.EvalContext, error) {
	defs := defRegistry(b)
	vars, err := blockVars(b, "", defs)
	if err != nil {
		return nil, err
	}
	if ctx.Variables == nil {
		ctx.Variables = make(map[string]cty.Value)
	}
	for k, v := range vars {
		ctx.Variables[k] = v
	}
	return ctx, nil
}

func blockVars(b *hclsyntax.Body, parentAddr string, defs *blockDef) (map[string]cty.Value, error) {
	vars := make(map[string]cty.Value)
	for name, def := range defs.children {
		v := make(map[string]cty.Value)
		blocks := blocksOfType(b.Blocks, name)
		if len(blocks) == 0 {
			v[name] = cty.NullVal(def.asCty())
		}
		var unlabeled int
		for _, blk := range blocks {
			blkName := blockName(blk)
			if blkName == "" {
				blkName = strconv.Itoa(unlabeled)
				unlabeled++
			}
			attrs := attrMap(blk.Body.Attributes)
			// Fill missing attributes with zero values.
			for n := range def.fields {
				if _, ok := attrs[n]; !ok {
					attrs[n] = cty.NullVal(ctySchemaLit)
				}
			}
			self := addr(parentAddr, name, blkName)
			attrs["__ref"] = cty.StringVal(self)
			varMap, err := blockVars(blk.Body, self, def)
			if err != nil {
				return nil, err
			}
			// Merge children blocks in.
			for k, v := range varMap {
				attrs[k] = v
			}

			v[blkName] = cty.ObjectVal(attrs)
		}
		if len(v) > 0 {
			vars[name] = cty.ObjectVal(v)
		}
	}
	return vars, nil
}

func addr(parentAddr, typeName, blkName string) string {
	var prefixDot string
	if len(parentAddr) > 0 {
		prefixDot = "."
	}
	return fmt.Sprintf("%s%s$%s.%s", parentAddr, prefixDot, typeName, blkName)
}

func blockName(blk *hclsyntax.Block) string {
	if len(blk.Labels) == 0 {
		return ""
	}
	return blk.Labels[0]
}

func blocksOfType(blocks hclsyntax.Blocks, typeName string) []*hclsyntax.Block {
	var out []*hclsyntax.Block
	for _, block := range blocks {
		if block.Type == typeName {
			out = append(out, block)
		}
	}
	return out
}

func attrMap(attrs hclsyntax.Attributes) map[string]cty.Value {
	out := make(map[string]cty.Value)
	for _, v := range attrs {
		value, diag := v.Expr.Value(nil)
		if diag.HasErrors() {
			continue
		}
		literalValue, err := extractLiteralValue(value)
		if err != nil {
			continue
		}
		out[v.Name] = cty.CapsuleVal(ctySchemaLit, literalValue)
	}
	return out
}

// ctySchemaLit is a cty.Capsule type the encapsulates a schemaspec.LiteralValue.
var (
	ctySchemaLit = cty.CapsuleWithOps("lit", reflect.TypeOf(schemaspec.LiteralValue{}), &cty.CapsuleOps{
		// ConversionFrom facilitates reading the encapsulated type as a string, as is needed, for example,
		// when interpolating it in a string expression.
		ConversionFrom: func(src cty.Type) func(interface{}, cty.Path) (cty.Value, error) {
			if src != cty.String {
				return nil
			}
			return func(i interface{}, path cty.Path) (cty.Value, error) {
				lit, ok := i.(*schemaspec.LiteralValue)
				if !ok {
					return cty.Value{}, fmt.Errorf("schemahcl: expected *schemaspec.LiteralValue got %T", i)
				}
				uq, err := strconv.Unquote(lit.V)
				if err != nil {
					return cty.StringVal(lit.V), nil
				}
				return cty.StringVal(uq), nil
			}
		},
	})
	ctyTypeSpec = cty.Capsule("type", reflect.TypeOf(schemaspec.Type{}))
	ctyRawExpr  = cty.Capsule("raw_expr", reflect.TypeOf(schemaspec.RawExpr{}))
)

// defRegistry returns a tree of blockDef structs representing the schema of the
// blocks in the *hclsyntax.Body. The returned fields and children of each type
// are an intersection of all existing blocks of the same type.
func defRegistry(b *hclsyntax.Body) *blockDef {
	reg := &blockDef{
		fields:   make(map[string]struct{}),
		children: make(map[string]*blockDef),
	}
	for _, blk := range b.Blocks {
		reg.child(extractDef(blk, reg))
	}
	return reg
}

// blockDef describes a type of block in the HCL document.
type blockDef struct {
	name     string
	fields   map[string]struct{}
	parent   *blockDef
	children map[string]*blockDef
}

// child updates the definition for the child type of the blockDef.
func (t *blockDef) child(c *blockDef) {
	ex, ok := t.children[c.name]
	if !ok {
		t.children[c.name] = c
		return
	}
	for f := range c.fields {
		ex.fields[f] = struct{}{}
	}
	for _, c := range c.children {
		ex.child(c)
	}
}

// asCty returns a cty.Type representing the blockDef.
func (t *blockDef) asCty() cty.Type {
	f := make(map[string]cty.Type)
	for attr := range t.fields {
		f[attr] = ctySchemaLit
	}
	f["__ref"] = cty.String
	for _, c := range t.children {
		f[c.name] = c.asCty()
	}
	return cty.Object(f)
}

func extractDef(blk *hclsyntax.Block, parent *blockDef) *blockDef {
	cur := &blockDef{
		name:     blk.Type,
		parent:   parent,
		fields:   make(map[string]struct{}),
		children: make(map[string]*blockDef),
	}
	for _, a := range blk.Body.Attributes {
		cur.fields[a.Name] = struct{}{}
	}
	for _, c := range blk.Body.Blocks {
		cur.child(extractDef(c, cur))
	}
	return cur
}
