// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package specutil

import (
	"fmt"
	"strconv"

	"ariga.io/atlas/schemahcl"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlspec"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// StrAttr is a helper method for constructing *schemahcl.Attr of type string.
func StrAttr(k, v string) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.LiteralValue{V: strconv.Quote(v)},
	}
}

// BoolAttr is a helper method for constructing *schemahcl.Attr of type bool.
func BoolAttr(k string, v bool) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.LiteralValue{V: strconv.FormatBool(v)},
	}
}

// IntAttr is a helper method for constructing *schemahcl.Attr with the numeric value of v.
func IntAttr(k string, v int) *schemahcl.Attr {
	return Int64Attr(k, int64(v))
}

// Int64Attr is a helper method for constructing *schemahcl.Attr with the numeric value of v.
func Int64Attr(k string, v int64) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.LiteralValue{V: strconv.FormatInt(v, 10)},
	}
}

// LitAttr is a helper method for constructing *schemahcl.Attr instances that contain literal values.
func LitAttr(k, v string) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.LiteralValue{V: v},
	}
}

// RawAttr is a helper method for constructing *schemahcl.Attr instances that contain sql expressions.
func RawAttr(k, v string) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.RawExpr{X: v},
	}
}

// VarAttr is a helper method for constructing *schemahcl.Attr instances that contain a variable reference.
func VarAttr(k, v string) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: &schemahcl.Ref{V: v},
	}
}

// RefAttr is a helper method for constructing *schemahcl.Attr instances that contain a reference.
func RefAttr(k string, r *schemahcl.Ref) *schemahcl.Attr {
	return &schemahcl.Attr{
		K: k,
		V: r,
	}
}

// ListAttr is a helper method for constructing *schemahcl.Attr instances that contain list values.
func ListAttr(k string, litValues ...string) *schemahcl.Attr {
	lv := &schemahcl.ListValue{}
	for _, v := range litValues {
		lv.V = append(lv.V, &schemahcl.LiteralValue{V: v})
	}
	return &schemahcl.Attr{
		K: k,
		V: lv,
	}
}

type doc struct {
	Tables  []*sqlspec.Table  `spec:"table"`
	Schemas []*sqlspec.Schema `spec:"schema"`
}

// Marshal marshals v into an Atlas DDL document using a schemahcl.Marshaler. Marshal uses the given
// schemaSpec function to convert a *schema.Schema into *sqlspec.Schema and []*sqlspec.Table.
func Marshal(v any, marshaler schemahcl.Marshaler, schemaSpec func(schem *schema.Schema) (*sqlspec.Schema, []*sqlspec.Table, error)) ([]byte, error) {
	d := &doc{}
	switch s := v.(type) {
	case *schema.Schema:
		spec, tables, err := schemaSpec(s)
		if err != nil {
			return nil, fmt.Errorf("specutil: failed converting schema to spec: %w", err)
		}
		d.Tables = tables
		d.Schemas = []*sqlspec.Schema{spec}
	case *schema.Realm:
		for _, s := range s.Schemas {
			spec, tables, err := schemaSpec(s)
			if err != nil {
				return nil, fmt.Errorf("specutil: failed converting schema to spec: %w", err)
			}
			d.Tables = append(d.Tables, tables...)
			d.Schemas = append(d.Schemas, spec)
		}
		if err := QualifyDuplicates(d.Tables); err != nil {
			return nil, err
		}
		if err := QualifyReferences(d.Tables, s); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("specutil: failed marshaling spec. %T is not supported", v)
	}
	return marshaler.MarshalSpec(d)
}

// QualifyDuplicates sets the Qualified field equal to the schema name in any tables
// with duplicate names in the provided table specs.
func QualifyDuplicates(tableSpecs []*sqlspec.Table) error {
	seen := make(map[string]*sqlspec.Table, len(tableSpecs))
	for _, tbl := range tableSpecs {
		if s, ok := seen[tbl.Name]; ok {
			schemaName, err := SchemaName(s.Schema)
			if err != nil {
				return err
			}
			s.Qualifier = schemaName
			schemaName, err = SchemaName(tbl.Schema)
			if err != nil {
				return err
			}
			tbl.Qualifier = schemaName
		}
		seen[tbl.Name] = tbl
	}
	return nil
}

// QualifyReferences qualifies any reference with qualifier.
func QualifyReferences(tableSpecs []*sqlspec.Table, realm *schema.Realm) error {
	type cref struct{ s, t string }
	byRef := make(map[cref]*sqlspec.Table)
	for _, t := range tableSpecs {
		r := cref{s: t.Qualifier, t: t.Name}
		if byRef[r] != nil {
			return fmt.Errorf("duplicate references were found for: %v", r)
		}
		byRef[r] = t
	}
	for _, t := range tableSpecs {
		sname, err := SchemaName(t.Schema)
		if err != nil {
			return err
		}
		s1, ok := realm.Schema(sname)
		if !ok {
			return fmt.Errorf("schema %q was not found in realm", sname)
		}
		t1, ok := s1.Table(t.Name)
		if !ok {
			return fmt.Errorf("table %q.%q was not found in realm", sname, t.Name)
		}
		for _, fk := range t.ForeignKeys {
			fk1, ok := t1.ForeignKey(fk.Symbol)
			if !ok {
				return fmt.Errorf("table %q.%q.%q was not found in realm", sname, t.Name, fk.Symbol)
			}
			for i, c := range fk.RefColumns {
				if r, ok := byRef[cref{s: fk1.RefTable.Schema.Name, t: fk1.RefTable.Name}]; ok && r.Qualifier != "" {
					fk.RefColumns[i] = qualifiedExternalColRef(fk1.RefColumns[i].Name, r.Name, r.Qualifier)
				} else if r, ok := byRef[cref{t: fk1.RefTable.Name}]; ok && r.Qualifier == "" {
					fk.RefColumns[i] = externalColRef(fk1.RefColumns[i].Name, r.Name)
				} else {
					return fmt.Errorf("missing reference for column %q in %q.%q.%q", c.V, sname, t.Name, fk.Symbol)
				}
			}
		}
	}
	return nil
}

// HCLBytesFunc returns a helper that evaluates an HCL document from a byte slice instead
// of from an hclparse.Parser instance.
func HCLBytesFunc(ev schemahcl.Evaluator) func(b []byte, v any, inp map[string]string) error {
	return func(b []byte, v any, inp map[string]string) error {
		parser := hclparse.NewParser()
		if _, diag := parser.ParseHCL(b, ""); diag.HasErrors() {
			return diag
		}
		return ev.Eval(parser, v, inp)
	}
}
