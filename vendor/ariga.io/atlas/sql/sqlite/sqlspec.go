// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlite

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"ariga.io/atlas/schemahcl"
	"ariga.io/atlas/sql/internal/specutil"
	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlspec"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// evalSpec evaluates an Atlas DDL document using an unmarshaler into v by using the input.
func evalSpec(p *hclparse.Parser, v any, input map[string]string) error {
	var d doc
	if err := hclState.Eval(p, &d, input); err != nil {
		return err
	}
	switch v := v.(type) {
	case *schema.Realm:
		err := specutil.Scan(v, d.Schemas, d.Tables, convertTable)
		if err != nil {
			return fmt.Errorf("specutil: failed converting to *schema.Realm: %w", err)
		}
	case *schema.Schema:
		if len(d.Schemas) != 1 {
			return fmt.Errorf("specutil: expecting document to contain a single schema, got %d", len(d.Schemas))
		}
		var r schema.Realm
		if err := specutil.Scan(&r, d.Schemas, d.Tables, convertTable); err != nil {
			return err
		}
		r.Schemas[0].Realm = nil
		*v = *r.Schemas[0]
	default:
		return fmt.Errorf("specutil: failed unmarshaling spec. %T is not supported", v)
	}
	return nil
}

// MarshalSpec marshals v into an Atlas DDL document using a schemahcl.Marshaler.
func MarshalSpec(v any, marshaler schemahcl.Marshaler) ([]byte, error) {
	return specutil.Marshal(v, marshaler, schemaSpec)
}

// convertTable converts a sqlspec.Table to a schema.Table. Table conversion is done without converting
// ForeignKeySpecs into ForeignKeys, as the target tables do not necessarily exist in the schema
// at this point. Instead, the linking is done by the convertSchema function.
func convertTable(spec *sqlspec.Table, parent *schema.Schema) (*schema.Table, error) {
	return specutil.Table(spec, parent, convertColumn, specutil.PrimaryKey, convertIndex, specutil.Check)
}

// convertIndex converts a sqlspec.Index into a schema.Index.
func convertIndex(spec *sqlspec.Index, t *schema.Table) (*schema.Index, error) {
	idx, err := specutil.Index(spec, t)
	if err != nil {
		return nil, err
	}
	if attr, ok := spec.Attr("where"); ok {
		p, err := attr.String()
		if err != nil {
			return nil, err
		}
		idx.Attrs = append(idx.Attrs, &IndexPredicate{P: p})
	}
	return idx, nil
}

// convertColumn converts a sqlspec.Column into a schema.Column.
func convertColumn(spec *sqlspec.Column, _ *schema.Table) (*schema.Column, error) {
	c, err := specutil.Column(spec, convertColumnType)
	if err != nil {
		return nil, err
	}
	if attr, ok := spec.Attr("auto_increment"); ok {
		b, err := attr.Bool()
		if err != nil {
			return nil, err
		}
		if b {
			c.AddAttrs(&AutoIncrement{})
		}
	}
	if err := specutil.ConvertGenExpr(spec.Remain(), c, storedOrVirtual); err != nil {
		return nil, err
	}
	return c, nil
}

// convertColumnType converts a sqlspec.Column into a concrete SQLite schema.Type.
func convertColumnType(spec *sqlspec.Column) (schema.Type, error) {
	return TypeRegistry.Type(spec.Type, spec.Extra.Attrs)
}

// schemaSpec converts from a concrete SQLite schema to Atlas specification.
func schemaSpec(schem *schema.Schema) (*sqlspec.Schema, []*sqlspec.Table, error) {
	return specutil.FromSchema(schem, tableSpec)
}

// tableSpec converts from a concrete SQLite sqlspec.Table to a schema.Table.
func tableSpec(tab *schema.Table) (*sqlspec.Table, error) {
	return specutil.FromTable(
		tab,
		columnSpec,
		specutil.FromPrimaryKey,
		indexSpec,
		specutil.FromForeignKey,
		specutil.FromCheck,
	)
}

func indexSpec(idx *schema.Index) (*sqlspec.Index, error) {
	spec, err := specutil.FromIndex(idx)
	if err != nil {
		return nil, err
	}
	if i := (IndexPredicate{}); sqlx.Has(idx.Attrs, &i) && i.P != "" {
		spec.Extra.Attrs = append(spec.Extra.Attrs, specutil.VarAttr("where", strconv.Quote(i.P)))
	}
	return spec, nil
}

// columnSpec converts from a concrete SQLite schema.Column into a sqlspec.Column.
func columnSpec(c *schema.Column, _ *schema.Table) (*sqlspec.Column, error) {
	s, err := specutil.FromColumn(c, columnTypeSpec)
	if err != nil {
		return nil, err
	}
	if sqlx.Has(c.Attrs, &AutoIncrement{}) {
		s.Extra.Attrs = append(s.Extra.Attrs, specutil.BoolAttr("auto_increment", true))
	}
	if x := (schema.GeneratedExpr{}); sqlx.Has(c.Attrs, &x) {
		s.Extra.Children = append(s.Extra.Children, specutil.FromGenExpr(x, storedOrVirtual))
	}
	return s, nil
}

// columnTypeSpec converts from a concrete MySQL schema.Type into sqlspec.Column Type.
func columnTypeSpec(t schema.Type) (*sqlspec.Column, error) {
	st, err := TypeRegistry.Convert(t)
	if err != nil {
		return nil, err
	}
	return &sqlspec.Column{Type: st}, nil
}

// TypeRegistry contains the supported TypeSpecs for the sqlite driver.
var TypeRegistry = schemahcl.NewRegistry(
	schemahcl.WithFormatter(FormatType),
	schemahcl.WithParser(ParseType),
	schemahcl.WithSpecs(
		schemahcl.NewTypeSpec(TypeReal, schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemahcl.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		schemahcl.NewTypeSpec(TypeBlob, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec(TypeText, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec(TypeInteger, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("int", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("tinyint", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("smallint", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("mediumint", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("bigint", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.AliasTypeSpec("unsigned_big_int", "unsigned big int", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("int2", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("int8", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("double", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.AliasTypeSpec("double_precision", "double precision", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("float", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("character", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("varchar", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.AliasTypeSpec("varying_character", "varying character", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("nchar", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.AliasTypeSpec("native_character", "native character", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("nvarchar", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("clob", schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec("numeric", schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemahcl.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		schemahcl.NewTypeSpec("decimal", schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemahcl.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		schemahcl.NewTypeSpec("bool"),
		schemahcl.NewTypeSpec("boolean"),
		schemahcl.NewTypeSpec("date"),
		schemahcl.NewTypeSpec("datetime"),
		schemahcl.NewTypeSpec("json"),
		schemahcl.NewTypeSpec("uuid"),
	),
)

var (
	hclState = schemahcl.New(
		schemahcl.WithTypes(TypeRegistry.Specs()),
		schemahcl.WithScopedEnums("table.column.as.type", stored, virtual),
		schemahcl.WithScopedEnums("table.foreign_key.on_update", specutil.ReferenceVars...),
		schemahcl.WithScopedEnums("table.foreign_key.on_delete", specutil.ReferenceVars...),
	)
	// MarshalHCL marshals v into an Atlas HCL DDL document.
	MarshalHCL = schemahcl.MarshalerFunc(func(v any) ([]byte, error) {
		return MarshalSpec(v, hclState)
	})
	// EvalHCL implements the schemahcl.Evaluator interface.
	EvalHCL = schemahcl.EvalFunc(evalSpec)

	// EvalHCLBytes is a helper that evaluates an HCL document from a byte slice instead
	// of from an hclparse.Parser instance.
	EvalHCLBytes = specutil.HCLBytesFunc(EvalHCL)
)

// storedOrVirtual returns a STORED or VIRTUAL
// generated type option based on the given string.
func storedOrVirtual(s string) string {
	if s = strings.ToUpper(s); s == "" {
		return virtual
	}
	return s
}

type doc struct {
	Tables  []*sqlspec.Table  `spec:"table"`
	Schemas []*sqlspec.Schema `spec:"schema"`
}
