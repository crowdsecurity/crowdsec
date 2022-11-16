// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schemahcl

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// varDef is an HCL resource that defines an input variable to the Atlas DDL document.
type varDef struct {
	Name    string    `hcl:",label"`
	Type    cty.Value `hcl:"type"`
	Default cty.Value `hcl:"default,optional"`
}

// setInputVals sets the input values into the evaluation context. HCL documents can define
// input variables in the document body by defining "variable" blocks:
//
//	variable "name" {
//	  type = string // also supported: int, bool
//	  default = "rotemtam"
//	}
func (s *State) setInputVals(ctx *hcl.EvalContext, body hcl.Body, input map[string]string) error {
	var c struct {
		Vars   []*varDef `hcl:"variable,block"`
		Remain hcl.Body  `hcl:",remain"`
	}
	nctx := ctx.NewChild()
	nctx.Variables = map[string]cty.Value{
		"string": capsuleTypeVal("string"),
		"int":    capsuleTypeVal("int"),
		"bool":   capsuleTypeVal("bool"),
	}
	if diag := gohcl.DecodeBody(body, nctx, &c); diag.HasErrors() {
		return diag
	}
	ctxVars := make(map[string]cty.Value)
	for _, v := range c.Vars {
		inputVal, ok := input[v.Name]
		if ok {
			ctyVal, err := readVar(v, inputVal)
			if err != nil {
				return fmt.Errorf("failed reading var: %w", err)
			}
			ctxVars[v.Name] = ctyVal
			continue
		}
		if v.Default == cty.NilVal {
			return fmt.Errorf("missing value for required variable %q", v.Name)
		}
		ctxVars[v.Name] = v.Default
	}
	mergeCtxVar(ctx, ctxVars)
	return nil
}

func mergeCtxVar(ctx *hcl.EvalContext, vals map[string]cty.Value) {
	const key = "var"
	v, ok := ctx.Variables[key]
	if ok {
		v.ForEachElement(func(key cty.Value, val cty.Value) (stop bool) {
			vals[key.AsString()] = val
			return false
		})
	}
	ctx.Variables[key] = cty.ObjectVal(vals)
}

// readVar reads the raw inputVal as a cty.Value using the type definition on v.
func readVar(v *varDef, inputVal string) (cty.Value, error) {
	et := v.Type.EncapsulatedValue()
	typ, ok := et.(*Type)
	if !ok {
		return cty.NilVal, fmt.Errorf("expected schemahcl.Type got %T", et)
	}
	switch typ.T {
	case "string":
		return cty.StringVal(inputVal), nil
	case "int":
		i, err := strconv.Atoi(inputVal)
		if err != nil {
			return cty.NilVal, err
		}
		return cty.NumberIntVal(int64(i)), nil
	case "bool":
		b, err := strconv.ParseBool(inputVal)
		if err != nil {
			return cty.NilVal, err
		}
		return cty.BoolVal(b), nil
	default:
		return cty.NilVal, fmt.Errorf("unknown type: %q", typ.T)
	}
}

func capsuleTypeVal(t string) cty.Value {
	return cty.CapsuleVal(ctyTypeSpec, &Type{T: t})
}

func setBlockVars(ctx *hcl.EvalContext, b *hclsyntax.Body) (*hcl.EvalContext, error) {
	defs := defRegistry(b)
	vars, err := blockVars(b.Blocks, "", defs)
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

func blockVars(blocks hclsyntax.Blocks, parentAddr string, defs *blockDef) (map[string]cty.Value, error) {
	vars := make(map[string]cty.Value)
	for name, def := range defs.children {
		v := make(map[string]cty.Value)
		qv := make(map[string]map[string]cty.Value)
		blocks := blocksOfType(blocks, name)
		if len(blocks) == 0 {
			vars[name] = cty.NullVal(def.asCty())
			continue
		}
		var unlabeled int
		for _, blk := range blocks {
			qualifier, blkName := blockName(blk)
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
			self := addr(parentAddr, name, blkName, qualifier)
			attrs["__ref"] = cty.StringVal(self)
			varMap, err := blockVars(blk.Body.Blocks, self, def)
			if err != nil {
				return nil, err
			}
			// Merge children blocks in.
			for k, v := range varMap {
				attrs[k] = v
			}
			switch {
			case qualifier != "":
				obj := cty.ObjectVal(attrs)
				if _, ok := qv[qualifier]; !ok {
					qv[qualifier] = make(map[string]cty.Value)
				}
				qv[qualifier][blkName] = obj
				obj = cty.ObjectVal(qv[qualifier])
				v[qualifier] = obj
			default:
				v[blkName] = cty.ObjectVal(attrs)
			}
		}
		if len(v) > 0 {
			vars[name] = cty.ObjectVal(v)
		}
	}
	return vars, nil
}

func addr(parentAddr, typeName, blkName, qualifier string) string {
	var prefixDot string
	if len(parentAddr) > 0 {
		prefixDot = "."
	}
	suffix := blkName
	if qualifier != "" {
		suffix = qualifier + "." + blkName
	}
	return fmt.Sprintf("%s%s$%s.%s", parentAddr, prefixDot, typeName, suffix)
}

func blockName(blk *hclsyntax.Block) (qualifier string, name string) {
	switch len(blk.Labels) {
	case 0:
	case 1:
		name = blk.Labels[0]
	default:
		qualifier = blk.Labels[0]
		name = blk.Labels[1]
	}
	return
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

// ctySchemaLit is a cty.Capsule type the encapsulates a schemahcl.LiteralValue.
var (
	ctySchemaLit = cty.CapsuleWithOps("lit", reflect.TypeOf(LiteralValue{}), &cty.CapsuleOps{
		// ConversionFrom facilitates reading the encapsulated type as a string, as is needed, for example,
		// when interpolating it in a string expression.
		ConversionFrom: func(src cty.Type) func(any, cty.Path) (cty.Value, error) {
			if src != cty.String {
				return nil
			}
			return func(i any, path cty.Path) (cty.Value, error) {
				lit, ok := i.(*LiteralValue)
				if !ok {
					return cty.Value{}, fmt.Errorf("schemahcl: expected *schemahcl.LiteralValue got %T", i)
				}
				uq, err := strconv.Unquote(lit.V)
				if err != nil {
					return cty.StringVal(lit.V), nil
				}
				return cty.StringVal(uq), nil
			}
		},
	})
	ctyTypeSpec = cty.Capsule("type", reflect.TypeOf(Type{}))
	ctyRawExpr  = cty.Capsule("raw_expr", reflect.TypeOf(RawExpr{}))
)

// varBlock is the block type for variable declarations.
const varBlock = "variable"

// defRegistry returns a tree of blockDef structs representing the schema of the
// blocks in the *hclsyntax.Body. The returned fields and children of each type
// are an intersection of all existing blocks of the same type.
func defRegistry(b *hclsyntax.Body) *blockDef {
	reg := &blockDef{
		fields:   make(map[string]struct{}),
		children: make(map[string]*blockDef),
	}
	for _, blk := range b.Blocks {
		// variable definition blocks are available in the HCL source but not reachable by reference.
		if blk.Type == varBlock {
			continue
		}
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
