// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package postgres

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

type (
	doc struct {
		Tables  []*sqlspec.Table  `spec:"table"`
		Enums   []*Enum           `spec:"enum"`
		Schemas []*sqlspec.Schema `spec:"schema"`
	}
	// Enum holds a specification for an enum, that can be referenced as a column type.
	Enum struct {
		Name   string         `spec:",name"`
		Schema *schemahcl.Ref `spec:"schema"`
		Values []string       `spec:"values"`
		schemahcl.DefaultExtension
	}
)

func init() {
	schemahcl.Register("enum", &Enum{})
}

// evalSpec evaluates an Atlas DDL document into v using the input.
func evalSpec(p *hclparse.Parser, v any, input map[string]string) error {
	var d doc
	if err := hclState.Eval(p, &d, input); err != nil {
		return err
	}
	switch v := v.(type) {
	case *schema.Realm:
		if err := specutil.Scan(v, d.Schemas, d.Tables, convertTable); err != nil {
			return fmt.Errorf("specutil: failed converting to *schema.Realm: %w", err)
		}
		if len(d.Enums) > 0 {
			if err := convertEnums(d.Tables, d.Enums, v); err != nil {
				return err
			}
		}
	case *schema.Schema:
		if len(d.Schemas) != 1 {
			return fmt.Errorf("specutil: expecting document to contain a single schema, got %d", len(d.Schemas))
		}
		r := &schema.Realm{}
		if err := specutil.Scan(r, d.Schemas, d.Tables, convertTable); err != nil {
			return err
		}
		if err := convertEnums(d.Tables, d.Enums, r); err != nil {
			return err
		}
		*v = *r.Schemas[0]
	default:
		return fmt.Errorf("specutil: failed unmarshaling spec. %T is not supported", v)
	}
	return nil
}

// MarshalSpec marshals v into an Atlas DDL document using a schemahcl.Marshaler.
func MarshalSpec(v any, marshaler schemahcl.Marshaler) ([]byte, error) {
	var d doc
	switch s := v.(type) {
	case *schema.Schema:
		var err error
		doc, err := schemaSpec(s)
		if err != nil {
			return nil, fmt.Errorf("specutil: failed converting schema to spec: %w", err)
		}
		d.Tables = doc.Tables
		d.Schemas = doc.Schemas
		d.Enums = doc.Enums
	case *schema.Realm:
		for _, s := range s.Schemas {
			doc, err := schemaSpec(s)
			if err != nil {
				return nil, fmt.Errorf("specutil: failed converting schema to spec: %w", err)
			}
			d.Tables = append(d.Tables, doc.Tables...)
			d.Schemas = append(d.Schemas, doc.Schemas...)
			d.Enums = append(d.Enums, doc.Enums...)
		}
		if err := specutil.QualifyDuplicates(d.Tables); err != nil {
			return nil, err
		}
		if err := specutil.QualifyReferences(d.Tables, s); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("specutil: failed marshaling spec. %T is not supported", v)
	}
	return marshaler.MarshalSpec(&d)
}

var (
	hclState = schemahcl.New(
		schemahcl.WithTypes(TypeRegistry.Specs()),
		schemahcl.WithScopedEnums("table.index.type", IndexTypeBTree, IndexTypeHash, IndexTypeGIN, IndexTypeGiST, IndexTypeBRIN),
		schemahcl.WithScopedEnums("table.partition.type", PartitionTypeRange, PartitionTypeList, PartitionTypeHash),
		schemahcl.WithScopedEnums("table.column.identity.generated", GeneratedTypeAlways, GeneratedTypeByDefault),
		schemahcl.WithScopedEnums("table.column.as.type", "STORED"),
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

// convertTable converts a sqlspec.Table to a schema.Table. Table conversion is done without converting
// ForeignKeySpecs into ForeignKeys, as the target tables do not necessarily exist in the schema
// at this point. Instead, the linking is done by the convertSchema function.
func convertTable(spec *sqlspec.Table, parent *schema.Schema) (*schema.Table, error) {
	t, err := specutil.Table(spec, parent, convertColumn, specutil.PrimaryKey, convertIndex, specutil.Check)
	if err != nil {
		return nil, err
	}
	if err := convertPartition(spec.Extra, t); err != nil {
		return nil, err
	}
	return t, nil
}

// convertPartition converts and appends the partition block into the table attributes if exists.
func convertPartition(spec schemahcl.Resource, table *schema.Table) error {
	r, ok := spec.Resource("partition")
	if !ok {
		return nil
	}
	var p struct {
		Type    string           `spec:"type"`
		Columns []*schemahcl.Ref `spec:"columns"`
		Parts   []*struct {
			Expr   string         `spec:"expr"`
			Column *schemahcl.Ref `spec:"column"`
		} `spec:"by"`
	}
	if err := r.As(&p); err != nil {
		return fmt.Errorf("parsing %s.partition: %w", table.Name, err)
	}
	if p.Type == "" {
		return fmt.Errorf("missing attribute %s.partition.type", table.Name)
	}
	key := &Partition{T: p.Type}
	switch n, m := len(p.Columns), len(p.Parts); {
	case n == 0 && m == 0:
		return fmt.Errorf("missing columns or expressions for %s.partition", table.Name)
	case n > 0 && m > 0:
		return fmt.Errorf(`multiple definitions for %s.partition, use "columns" or "by"`, table.Name)
	case n > 0:
		for _, r := range p.Columns {
			c, err := specutil.ColumnByRef(table, r)
			if err != nil {
				return err
			}
			key.Parts = append(key.Parts, &PartitionPart{C: c})
		}
	case m > 0:
		for i, p := range p.Parts {
			switch {
			case p.Column == nil && p.Expr == "":
				return fmt.Errorf("missing column or expression for %s.partition.by at position %d", table.Name, i)
			case p.Column != nil && p.Expr != "":
				return fmt.Errorf("multiple definitions for  %s.partition.by at position %d", table.Name, i)
			case p.Column != nil:
				c, err := specutil.ColumnByRef(table, p.Column)
				if err != nil {
					return err
				}
				key.Parts = append(key.Parts, &PartitionPart{C: c})
			case p.Expr != "":
				key.Parts = append(key.Parts, &PartitionPart{X: &schema.RawExpr{X: p.Expr}})
			}
		}
	}
	table.AddAttrs(key)
	return nil
}

// fromPartition returns the resource spec for representing the partition block.
func fromPartition(p Partition) *schemahcl.Resource {
	key := &schemahcl.Resource{
		Type: "partition",
		Attrs: []*schemahcl.Attr{
			specutil.VarAttr("type", strings.ToUpper(specutil.Var(p.T))),
		},
	}
	columns, ok := func() (*schemahcl.ListValue, bool) {
		parts := make([]schemahcl.Value, 0, len(p.Parts))
		for _, p := range p.Parts {
			if p.C == nil {
				return nil, false
			}
			parts = append(parts, specutil.ColumnRef(p.C.Name))
		}
		return &schemahcl.ListValue{V: parts}, true
	}()
	if ok {
		key.Attrs = append(key.Attrs, &schemahcl.Attr{K: "columns", V: columns})
		return key
	}
	for _, p := range p.Parts {
		part := &schemahcl.Resource{Type: "by"}
		switch {
		case p.C != nil:
			part.Attrs = append(part.Attrs, specutil.RefAttr("column", specutil.ColumnRef(p.C.Name)))
		case p.X != nil:
			part.Attrs = append(part.Attrs, specutil.StrAttr("expr", p.X.(*schema.RawExpr).X))
		}
		key.Children = append(key.Children, part)
	}
	return key
}

// convertColumn converts a sqlspec.Column into a schema.Column.
func convertColumn(spec *sqlspec.Column, _ *schema.Table) (*schema.Column, error) {
	if err := fixDefaultQuotes(spec.Default); err != nil {
		return nil, err
	}
	c, err := specutil.Column(spec, convertColumnType)
	if err != nil {
		return nil, err
	}
	if r, ok := spec.Extra.Resource("identity"); ok {
		id, err := convertIdentity(r)
		if err != nil {
			return nil, err
		}
		c.Attrs = append(c.Attrs, id)
	}
	if err := specutil.ConvertGenExpr(spec.Remain(), c, generatedType); err != nil {
		return nil, err
	}
	return c, nil
}

func convertIdentity(r *schemahcl.Resource) (*Identity, error) {
	var spec struct {
		Generation string `spec:"generated"`
		Start      int64  `spec:"start"`
		Increment  int64  `spec:"increment"`
	}
	if err := r.As(&spec); err != nil {
		return nil, err
	}
	id := &Identity{Generation: specutil.FromVar(spec.Generation), Sequence: &Sequence{}}
	if spec.Start != 0 {
		id.Sequence.Start = spec.Start
	}
	if spec.Increment != 0 {
		id.Sequence.Increment = spec.Increment
	}
	return id, nil
}

// fixDefaultQuotes fixes the quotes on the Default field to be single quotes
// instead of double quotes.
func fixDefaultQuotes(value schemahcl.Value) error {
	lv, ok := value.(*schemahcl.LiteralValue)
	if !ok {
		return nil
	}
	if sqlx.IsQuoted(lv.V, '"') {
		uq, err := strconv.Unquote(lv.V)
		if err != nil {
			return err
		}
		lv.V = "'" + uq + "'"
	}
	return nil
}

// convertIndex converts a sqlspec.Index into a schema.Index.
func convertIndex(spec *sqlspec.Index, t *schema.Table) (*schema.Index, error) {
	idx, err := specutil.Index(spec, t)
	if err != nil {
		return nil, err
	}
	if attr, ok := spec.Attr("type"); ok {
		t, err := attr.String()
		if err != nil {
			return nil, err
		}
		idx.Attrs = append(idx.Attrs, &IndexType{T: t})
	}
	if attr, ok := spec.Attr("where"); ok {
		p, err := attr.String()
		if err != nil {
			return nil, err
		}
		idx.Attrs = append(idx.Attrs, &IndexPredicate{P: p})
	}
	if attr, ok := spec.Attr("page_per_range"); ok {
		p, err := attr.Int64()
		if err != nil {
			return nil, err
		}
		idx.Attrs = append(idx.Attrs, &IndexStorageParams{PagesPerRange: p})
	}
	if attr, ok := spec.Attr("include"); ok {
		refs, err := attr.Refs()
		if err != nil {
			return nil, err
		}
		if len(refs) == 0 {
			return nil, fmt.Errorf("unexpected empty INCLUDE in index %q definition", spec.Name)
		}
		include := make([]*schema.Column, len(refs))
		for i, r := range refs {
			if include[i], err = specutil.ColumnByRef(t, r); err != nil {
				return nil, err
			}
		}
		idx.Attrs = append(idx.Attrs, &IndexInclude{Columns: include})
	}
	return idx, nil
}

const defaultTimePrecision = 6

// convertColumnType converts a sqlspec.Column into a concrete Postgres schema.Type.
func convertColumnType(spec *sqlspec.Column) (schema.Type, error) {
	typ, err := TypeRegistry.Type(spec.Type, spec.Extra.Attrs)
	if err != nil {
		return nil, err
	}
	// Handle default values for time precision types.
	if t, ok := typ.(*schema.TimeType); ok && strings.HasPrefix(t.T, "time") {
		if _, ok := attr(spec.Type, "precision"); !ok {
			p := defaultTimePrecision
			t.Precision = &p
		}
	}
	return typ, nil
}

// convertEnums converts possibly referenced column types (like enums) to
// an actual schema.Type and sets it on the correct schema.Column.
func convertEnums(tables []*sqlspec.Table, enums []*Enum, r *schema.Realm) error {
	var (
		used   = make(map[*Enum]struct{})
		byName = make(map[string]*Enum)
	)
	for _, e := range enums {
		byName[e.Name] = e
	}
	for _, t := range tables {
		for _, c := range t.Columns {
			var enum *Enum
			switch {
			case c.Type.IsRef:
				n, err := enumName(c.Type)
				if err != nil {
					return err
				}
				e, ok := byName[n]
				if !ok {
					return fmt.Errorf("enum %q was not found", n)
				}
				enum = e
			default:
				n, ok := arrayType(c.Type.T)
				if !ok || byName[n] == nil {
					continue
				}
				enum = byName[n]
			}
			used[enum] = struct{}{}
			schemaE, err := specutil.SchemaName(enum.Schema)
			if err != nil {
				return fmt.Errorf("extract schema name from enum refrence: %w", err)
			}
			es, ok := r.Schema(schemaE)
			if !ok {
				return fmt.Errorf("schema %q not found in realm for table %q", schemaE, t.Name)
			}
			schemaT, err := specutil.SchemaName(t.Schema)
			if err != nil {
				return fmt.Errorf("extract schema name from table refrence: %w", err)
			}
			ts, ok := r.Schema(schemaT)
			if !ok {
				return fmt.Errorf("schema %q not found in realm for table %q", schemaT, t.Name)
			}
			tt, ok := ts.Table(t.Name)
			if !ok {
				return fmt.Errorf("table %q not found in schema %q", t.Name, ts.Name)
			}
			cc, ok := tt.Column(c.Name)
			if !ok {
				return fmt.Errorf("column %q not found in table %q", c.Name, t.Name)
			}
			e := &schema.EnumType{T: enum.Name, Schema: es, Values: enum.Values}
			switch t := cc.Type.Type.(type) {
			case *ArrayType:
				t.Type = e
			default:
				cc.Type.Type = e
			}
		}
	}
	for _, e := range enums {
		if _, ok := used[e]; !ok {
			return fmt.Errorf("enum %q declared but not used", e.Name)
		}
	}
	return nil
}

// enumName extracts the name of the referenced Enum from the reference string.
func enumName(ref *schemahcl.Type) (string, error) {
	s := strings.Split(ref.T, "$enum.")
	if len(s) != 2 {
		return "", fmt.Errorf("postgres: failed to extract enum name from %q", ref.T)
	}
	return s[1], nil
}

// enumRef returns a reference string to the given enum name.
func enumRef(n string) *schemahcl.Ref {
	return &schemahcl.Ref{
		V: "$enum." + n,
	}
}

// schemaSpec converts from a concrete Postgres schema to Atlas specification.
func schemaSpec(schem *schema.Schema) (*doc, error) {
	s, tbls, err := specutil.FromSchema(schem, tableSpec)
	if err != nil {
		return nil, err
	}
	d := &doc{
		Tables:  tbls,
		Schemas: []*sqlspec.Schema{s},
	}
	enums := make(map[string]bool)
	for _, t := range schem.Tables {
		for _, c := range t.Columns {
			if e, ok := hasEnumType(c); ok && !enums[e.T] {
				d.Enums = append(d.Enums, &Enum{
					Name:   e.T,
					Schema: specutil.SchemaRef(s.Name),
					Values: e.Values,
				})
				enums[e.T] = true
			}
		}
	}
	return d, nil
}

// tableSpec converts from a concrete Postgres sqlspec.Table to a schema.Table.
func tableSpec(table *schema.Table) (*sqlspec.Table, error) {
	spec, err := specutil.FromTable(
		table,
		columnSpec,
		specutil.FromPrimaryKey,
		indexSpec,
		specutil.FromForeignKey,
		specutil.FromCheck,
	)
	if err != nil {
		return nil, err
	}
	if p := (Partition{}); sqlx.Has(table.Attrs, &p) {
		spec.Extra.Children = append(spec.Extra.Children, fromPartition(p))
	}
	return spec, nil
}

func indexSpec(idx *schema.Index) (*sqlspec.Index, error) {
	spec, err := specutil.FromIndex(idx)
	if err != nil {
		return nil, err
	}
	// Avoid printing the index type if it is the default.
	if i := (IndexType{}); sqlx.Has(idx.Attrs, &i) && i.T != IndexTypeBTree {
		spec.Extra.Attrs = append(spec.Extra.Attrs, specutil.VarAttr("type", strings.ToUpper(i.T)))
	}
	if i := (IndexInclude{}); sqlx.Has(idx.Attrs, &i) && len(i.Columns) > 0 {
		attr := &schemahcl.ListValue{}
		for _, c := range i.Columns {
			attr.V = append(attr.V, specutil.ColumnRef(c.Name))
		}
		spec.Extra.Attrs = append(spec.Extra.Attrs, &schemahcl.Attr{
			K: "include",
			V: attr,
		})
	}
	if i := (IndexPredicate{}); sqlx.Has(idx.Attrs, &i) && i.P != "" {
		spec.Extra.Attrs = append(spec.Extra.Attrs, specutil.VarAttr("where", strconv.Quote(i.P)))
	}
	if p, ok := indexStorageParams(idx.Attrs); ok {
		spec.Extra.Attrs = append(spec.Extra.Attrs, specutil.Int64Attr("page_per_range", p.PagesPerRange))
	}
	return spec, nil
}

// columnSpec converts from a concrete Postgres schema.Column into a sqlspec.Column.
func columnSpec(c *schema.Column, _ *schema.Table) (*sqlspec.Column, error) {
	s, err := specutil.FromColumn(c, columnTypeSpec)
	if err != nil {
		return nil, err
	}
	if i := (&Identity{}); sqlx.Has(c.Attrs, i) {
		s.Extra.Children = append(s.Extra.Children, fromIdentity(i))
	}
	if x := (schema.GeneratedExpr{}); sqlx.Has(c.Attrs, &x) {
		s.Extra.Children = append(s.Extra.Children, specutil.FromGenExpr(x, generatedType))
	}
	return s, nil
}

// fromIdentity returns the resource spec for representing the identity attributes.
func fromIdentity(i *Identity) *schemahcl.Resource {
	id := &schemahcl.Resource{
		Type: "identity",
		Attrs: []*schemahcl.Attr{
			specutil.VarAttr("generated", strings.ToUpper(specutil.Var(i.Generation))),
		},
	}
	if s := i.Sequence; s != nil {
		if s.Start != 1 {
			id.Attrs = append(id.Attrs, specutil.Int64Attr("start", s.Start))
		}
		if s.Increment != 1 {
			id.Attrs = append(id.Attrs, specutil.Int64Attr("increment", s.Increment))
		}
	}
	return id
}

// columnTypeSpec converts from a concrete Postgres schema.Type into sqlspec.Column Type.
func columnTypeSpec(t schema.Type) (*sqlspec.Column, error) {
	// Handle postgres enum types. They cannot be put into the TypeRegistry since their name is dynamic.
	if e, ok := t.(*schema.EnumType); ok {
		return &sqlspec.Column{Type: &schemahcl.Type{
			T:     enumRef(e.T).V,
			IsRef: true,
		}}, nil
	}
	st, err := TypeRegistry.Convert(t)
	if err != nil {
		return nil, err
	}
	return &sqlspec.Column{Type: st}, nil
}

// TypeRegistry contains the supported TypeSpecs for the Postgres driver.
var TypeRegistry = schemahcl.NewRegistry(
	schemahcl.WithSpecFunc(typeSpec),
	schemahcl.WithParser(ParseType),
	schemahcl.WithSpecs(
		schemahcl.NewTypeSpec(TypeBit, schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "len", Kind: reflect.Int64})),
		schemahcl.AliasTypeSpec("bit_varying", TypeBitVar, schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "len", Kind: reflect.Int64})),
		schemahcl.NewTypeSpec(TypeVarChar, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.AliasTypeSpec("character_varying", TypeCharVar, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec(TypeChar, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec(TypeCharacter, schemahcl.WithAttributes(schemahcl.SizeTypeAttr(false))),
		schemahcl.NewTypeSpec(TypeInt2),
		schemahcl.NewTypeSpec(TypeInt4),
		schemahcl.NewTypeSpec(TypeInt8),
		schemahcl.NewTypeSpec(TypeInt),
		schemahcl.NewTypeSpec(TypeInteger),
		schemahcl.NewTypeSpec(TypeSmallInt),
		schemahcl.NewTypeSpec(TypeBigInt),
		schemahcl.NewTypeSpec(TypeText),
		schemahcl.NewTypeSpec(TypeBoolean),
		schemahcl.NewTypeSpec(TypeBool),
		schemahcl.NewTypeSpec(TypeBytea),
		schemahcl.NewTypeSpec(TypeCIDR),
		schemahcl.NewTypeSpec(TypeInet),
		schemahcl.NewTypeSpec(TypeMACAddr),
		schemahcl.NewTypeSpec(TypeMACAddr8),
		schemahcl.NewTypeSpec(TypeCircle),
		schemahcl.NewTypeSpec(TypeLine),
		schemahcl.NewTypeSpec(TypeLseg),
		schemahcl.NewTypeSpec(TypeBox),
		schemahcl.NewTypeSpec(TypePath),
		schemahcl.NewTypeSpec(TypePoint),
		schemahcl.NewTypeSpec(TypePolygon),
		schemahcl.NewTypeSpec(TypeDate),
		schemahcl.NewTypeSpec(TypeTime, schemahcl.WithAttributes(precisionTypeAttr()), formatTime()),
		schemahcl.NewTypeSpec(TypeTimeTZ, schemahcl.WithAttributes(precisionTypeAttr()), formatTime()),
		schemahcl.NewTypeSpec(TypeTimestampTZ, schemahcl.WithAttributes(precisionTypeAttr()), formatTime()),
		schemahcl.NewTypeSpec(TypeTimestamp, schemahcl.WithAttributes(precisionTypeAttr()), formatTime()),
		schemahcl.AliasTypeSpec("double_precision", TypeDouble),
		schemahcl.NewTypeSpec(TypeReal),
		schemahcl.NewTypeSpec(TypeFloat, schemahcl.WithAttributes(precisionTypeAttr())),
		schemahcl.NewTypeSpec(TypeFloat8),
		schemahcl.NewTypeSpec(TypeFloat4),
		schemahcl.NewTypeSpec(TypeNumeric, schemahcl.WithAttributes(precisionTypeAttr(), &schemahcl.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		schemahcl.NewTypeSpec(TypeDecimal, schemahcl.WithAttributes(precisionTypeAttr(), &schemahcl.TypeAttr{Name: "scale", Kind: reflect.Int, Required: false})),
		schemahcl.NewTypeSpec(TypeSmallSerial),
		schemahcl.NewTypeSpec(TypeSerial),
		schemahcl.NewTypeSpec(TypeBigSerial),
		schemahcl.NewTypeSpec(TypeSerial2),
		schemahcl.NewTypeSpec(TypeSerial4),
		schemahcl.NewTypeSpec(TypeSerial8),
		schemahcl.NewTypeSpec(TypeXML),
		schemahcl.NewTypeSpec(TypeJSON),
		schemahcl.NewTypeSpec(TypeJSONB),
		schemahcl.NewTypeSpec(TypeUUID),
		schemahcl.NewTypeSpec(TypeMoney),
		schemahcl.NewTypeSpec("hstore"),
		schemahcl.NewTypeSpec("sql", schemahcl.WithAttributes(&schemahcl.TypeAttr{Name: "def", Required: true, Kind: reflect.String})),
	),
	schemahcl.WithSpecs(func() (specs []*schemahcl.TypeSpec) {
		opts := []schemahcl.TypeSpecOption{
			schemahcl.WithToSpec(func(t schema.Type) (*schemahcl.Type, error) {
				i, ok := t.(*IntervalType)
				if !ok {
					return nil, fmt.Errorf("postgres: unexpected interval type %T", t)
				}
				spec := &schemahcl.Type{T: TypeInterval}
				if i.F != "" {
					spec.T = specutil.Var(strings.ToLower(i.F))
				}
				if p := i.Precision; p != nil && *p != defaultTimePrecision {
					spec.Attrs = []*schemahcl.Attr{specutil.IntAttr("precision", *p)}
				}
				return spec, nil
			}),
			schemahcl.WithFromSpec(func(t *schemahcl.Type) (schema.Type, error) {
				i := &IntervalType{T: TypeInterval}
				if t.T != TypeInterval {
					i.F = specutil.FromVar(t.T)
				}
				if a, ok := attr(t, "precision"); ok {
					p, err := a.Int()
					if err != nil {
						return nil, fmt.Errorf(`postgres: parsing attribute "precision": %w`, err)
					}
					if p != defaultTimePrecision {
						i.Precision = &p
					}
				}
				return i, nil
			}),
		}
		for _, f := range []string{"interval", "second", "day to second", "hour to second", "minute to second"} {
			specs = append(specs, schemahcl.NewTypeSpec(specutil.Var(f), append(opts, schemahcl.WithAttributes(precisionTypeAttr()))...))
		}
		for _, f := range []string{"year", "month", "day", "hour", "minute", "year to month", "day to hour", "day to minute", "hour to minute"} {
			specs = append(specs, schemahcl.NewTypeSpec(specutil.Var(f), opts...))
		}
		return specs
	}()...),
)

func precisionTypeAttr() *schemahcl.TypeAttr {
	return &schemahcl.TypeAttr{
		Name:     "precision",
		Kind:     reflect.Int,
		Required: false,
	}
}

func attr(typ *schemahcl.Type, key string) (*schemahcl.Attr, bool) {
	for _, a := range typ.Attrs {
		if a.K == key {
			return a, true
		}
	}
	return nil, false
}

func typeSpec(t schema.Type) (*schemahcl.Type, error) {
	if t, ok := t.(*schema.TimeType); ok && t.T != TypeDate {
		spec := &schemahcl.Type{T: timeAlias(t.T)}
		if p := t.Precision; p != nil && *p != defaultTimePrecision {
			spec.Attrs = []*schemahcl.Attr{specutil.IntAttr("precision", *p)}
		}
		return spec, nil
	}
	s, err := FormatType(t)
	if err != nil {
		return nil, err
	}
	return &schemahcl.Type{T: s}, nil
}

// formatTime overrides the default printing logic done by schemahcl.hclType.
func formatTime() schemahcl.TypeSpecOption {
	return schemahcl.WithTypeFormatter(func(t *schemahcl.Type) (string, error) {
		a, ok := attr(t, "precision")
		if !ok {
			return t.T, nil
		}
		p, err := a.Int()
		if err != nil {
			return "", fmt.Errorf(`postgres: parsing attribute "precision": %w`, err)
		}
		return FormatType(&schema.TimeType{T: t.T, Precision: &p})
	})
}

// generatedType returns the default and only type for a generated column.
func generatedType(string) string { return "STORED" }
