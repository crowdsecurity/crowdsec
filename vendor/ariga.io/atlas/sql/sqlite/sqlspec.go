package sqlite

import (
	"reflect"

	"ariga.io/atlas/schema/schemaspec"
	"ariga.io/atlas/schema/schemaspec/schemahcl"
	"ariga.io/atlas/sql/internal/specutil"
	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlspec"
)

// UnmarshalSpec unmarshals an Atlas DDL document using an unmarshaler into v.
func UnmarshalSpec(data []byte, unmarshaler schemaspec.Unmarshaler, v interface{}) error {
	return specutil.Unmarshal(data, unmarshaler, v, convertTable)
}

// MarshalSpec marshals v into an Atlas DDL document using a schemaspec.Marshaler.
func MarshalSpec(v interface{}, marshaler schemaspec.Marshaler) ([]byte, error) {
	return specutil.Marshal(v, marshaler, schemaSpec)
}

// convertTable converts a sqlspec.Table to a schema.Table. Table conversion is done without converting
// ForeignKeySpecs into ForeignKeys, as the target tables do not necessarily exist in the schema
// at this point. Instead, the linking is done by the convertSchema function.
func convertTable(spec *sqlspec.Table, parent *schema.Schema) (*schema.Table, error) {
	return specutil.Table(spec, parent, convertColumn, specutil.PrimaryKey, specutil.Index, specutil.Check)
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
		specutil.FromIndex,
		specutil.FromForeignKey,
		specutil.FromCheck,
	)
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
var TypeRegistry = specutil.NewRegistry(
	specutil.WithFormatter(FormatType),
	specutil.WithParser(ParseType),
	specutil.WithSpecs(
		specutil.TypeSpec(TypeReal, specutil.WithAttributes(&schemaspec.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemaspec.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		specutil.TypeSpec(TypeBlob, specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec(TypeText, specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec(TypeInteger, specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("int", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("tinyint", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("smallint", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("mediumint", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("bigint", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.AliasTypeSpec("unsigned_big_int", "unsigned big int", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("int2", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("int8", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("double", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.AliasTypeSpec("double_precision", "double precision", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("float", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("character", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("varchar", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.AliasTypeSpec("varying_character", "varying character", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("nchar", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.AliasTypeSpec("native_character", "native character", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("nvarchar", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("clob", specutil.WithAttributes(specutil.SizeTypeAttr(false))),
		specutil.TypeSpec("numeric", specutil.WithAttributes(&schemaspec.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemaspec.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		specutil.TypeSpec("decimal", specutil.WithAttributes(&schemaspec.TypeAttr{Name: "precision", Kind: reflect.Int, Required: false}, &schemaspec.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		specutil.TypeSpec("boolean"),
		specutil.TypeSpec("date"),
		specutil.TypeSpec("datetime"),
		specutil.TypeSpec("json"),
		specutil.TypeSpec("uuid"),
	),
)

var (
	hclState = schemahcl.New(
		schemahcl.WithTypes(TypeRegistry.Specs()),
		schemahcl.WithScopedEnums("table.foreign_key.on_update", specutil.ReferenceVars...),
		schemahcl.WithScopedEnums("table.foreign_key.on_delete", specutil.ReferenceVars...),
	)
	// UnmarshalHCL unmarshals an Atlas HCL DDL document into v.
	UnmarshalHCL = schemaspec.UnmarshalerFunc(func(bytes []byte, i interface{}) error {
		return UnmarshalSpec(bytes, hclState, i)
	})
	// MarshalHCL marshals v into an Atlas HCL DDL document.
	MarshalHCL = schemaspec.MarshalerFunc(func(v interface{}) ([]byte, error) {
		return MarshalSpec(v, hclState)
	})
)
