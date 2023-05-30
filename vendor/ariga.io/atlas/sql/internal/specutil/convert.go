// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package specutil

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"ariga.io/atlas/schemahcl"
	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlspec"
)

// List of convert function types.
type (
	ConvertTableFunc      func(*sqlspec.Table, *schema.Schema) (*schema.Table, error)
	ConvertColumnFunc     func(*sqlspec.Column, *schema.Table) (*schema.Column, error)
	ConvertTypeFunc       func(*sqlspec.Column) (schema.Type, error)
	ConvertPrimaryKeyFunc func(*sqlspec.PrimaryKey, *schema.Table) (*schema.Index, error)
	ConvertIndexFunc      func(*sqlspec.Index, *schema.Table) (*schema.Index, error)
	ConvertCheckFunc      func(*sqlspec.Check) (*schema.Check, error)
	ColumnSpecFunc        func(*schema.Column, *schema.Table) (*sqlspec.Column, error)
	ColumnTypeSpecFunc    func(schema.Type) (*sqlspec.Column, error)
	TableSpecFunc         func(*schema.Table) (*sqlspec.Table, error)
	PrimaryKeySpecFunc    func(*schema.Index) (*sqlspec.PrimaryKey, error)
	IndexSpecFunc         func(*schema.Index) (*sqlspec.Index, error)
	ForeignKeySpecFunc    func(*schema.ForeignKey) (*sqlspec.ForeignKey, error)
	CheckSpecFunc         func(*schema.Check) *sqlspec.Check
)

// Scan populates the Realm from the schemas and table specs.
func Scan(r *schema.Realm, schemas []*sqlspec.Schema, tables []*sqlspec.Table, convertTable ConvertTableFunc) error {
	// Build the schemas.
	for _, schemaSpec := range schemas {
		sch := &schema.Schema{Name: schemaSpec.Name, Realm: r}
		for _, tableSpec := range tables {
			name, err := SchemaName(tableSpec.Schema)
			if err != nil {
				return fmt.Errorf("specutil: cannot extract schema name for table %q: %w", tableSpec.Name, err)
			}
			if name == schemaSpec.Name {
				tbl, err := convertTable(tableSpec, sch)
				if err != nil {
					return err
				}
				sch.Tables = append(sch.Tables, tbl)
			}
		}
		r.Schemas = append(r.Schemas, sch)
	}
	// Link the foreign keys.
	for _, sch := range r.Schemas {
		for _, tbl := range sch.Tables {
			tableSpec, err := findTableSpec(tables, sch.Name, tbl.Name)
			if err != nil {
				return err
			}
			if err := linkForeignKeys(tbl, sch, tableSpec); err != nil {
				return err
			}
		}
	}
	return nil
}

// findTableSpec searches tableSpecs for a spec of a table named tableName in a schema named schemaName.
func findTableSpec(tableSpecs []*sqlspec.Table, schemaName, tableName string) (*sqlspec.Table, error) {
	for _, tbl := range tableSpecs {
		n, err := SchemaName(tbl.Schema)
		if err != nil {
			return nil, err
		}
		if n == schemaName && tbl.Name == tableName {
			return tbl, nil
		}
	}
	return nil, fmt.Errorf("table %s.%s not found", schemaName, tableName)
}

// Table converts a sqlspec.Table to a schema.Table. Table conversion is done without converting
// ForeignKeySpecs into ForeignKeys, as the target tables do not necessarily exist in the schema
// at this point. Instead, the linking is done by the Schema function.
func Table(spec *sqlspec.Table, parent *schema.Schema, convertColumn ConvertColumnFunc,
	convertPK ConvertPrimaryKeyFunc, convertIndex ConvertIndexFunc, convertCheck ConvertCheckFunc) (*schema.Table, error) {
	tbl := &schema.Table{
		Name:   spec.Name,
		Schema: parent,
	}
	for _, csp := range spec.Columns {
		col, err := convertColumn(csp, tbl)
		if err != nil {
			return nil, err
		}
		tbl.Columns = append(tbl.Columns, col)
	}
	if spec.PrimaryKey != nil {
		pk, err := convertPK(spec.PrimaryKey, tbl)
		if err != nil {
			return nil, err
		}
		tbl.PrimaryKey = pk
	}
	for _, idx := range spec.Indexes {
		i, err := convertIndex(idx, tbl)
		if err != nil {
			return nil, err
		}
		tbl.Indexes = append(tbl.Indexes, i)
	}
	for _, c := range spec.Checks {
		c, err := convertCheck(c)
		if err != nil {
			return nil, err
		}
		tbl.AddChecks(c)
	}
	if err := convertCommentFromSpec(spec, &tbl.Attrs); err != nil {
		return nil, err
	}
	return tbl, nil
}

// Column converts a sqlspec.Column into a schema.Column.
func Column(spec *sqlspec.Column, conv ConvertTypeFunc) (*schema.Column, error) {
	out := &schema.Column{
		Name: spec.Name,
		Type: &schema.ColumnType{
			Null: spec.Null,
		},
	}
	if spec.Default != nil {
		switch d := spec.Default.(type) {
		case *schemahcl.LiteralValue:
			out.Default = &schema.Literal{V: d.V}
		case *schemahcl.RawExpr:
			out.Default = &schema.RawExpr{X: d.X}
		default:
			return nil, fmt.Errorf("unsupported value type for default: %T", d)
		}
	}
	ct, err := conv(spec)
	if err != nil {
		return nil, err
	}
	out.Type.Type = ct
	if err := convertCommentFromSpec(spec, &out.Attrs); err != nil {
		return nil, err
	}
	return out, err
}

// Index converts a sqlspec.Index to a schema.Index. The optional arguments allow
// passing functions for mutating the created index-part (e.g. add attributes).
func Index(spec *sqlspec.Index, parent *schema.Table, partFns ...func(*sqlspec.IndexPart, *schema.IndexPart) error) (*schema.Index, error) {
	parts := make([]*schema.IndexPart, 0, len(spec.Columns)+len(spec.Parts))
	switch n, m := len(spec.Columns), len(spec.Parts); {
	case n == 0 && m == 0:
		return nil, fmt.Errorf("missing definition for index %q", spec.Name)
	case n > 0 && m > 0:
		return nil, fmt.Errorf(`multiple definitions for index %q, use "columns" or "on"`, spec.Name)
	case n > 0:
		for i, c := range spec.Columns {
			c, err := ColumnByRef(parent, c)
			if err != nil {
				return nil, err
			}
			parts = append(parts, &schema.IndexPart{
				SeqNo: i,
				C:     c,
			})
		}
	case m > 0:
		for i, p := range spec.Parts {
			part := &schema.IndexPart{SeqNo: i, Desc: p.Desc}
			switch {
			case p.Column == nil && p.Expr == "":
				return nil, fmt.Errorf(`"column" or "expr" are required for index %q at position %d`, spec.Name, i)
			case p.Column != nil && p.Expr != "":
				return nil, fmt.Errorf(`cannot use both "column" and "expr" in index %q at position %d`, spec.Name, i)
			case p.Expr != "":
				part.X = &schema.RawExpr{X: p.Expr}
			case p.Column != nil:
				c, err := ColumnByRef(parent, p.Column)
				if err != nil {
					return nil, err
				}
				part.C = c
			}
			for _, f := range partFns {
				if err := f(p, part); err != nil {
					return nil, err
				}
			}
			parts = append(parts, part)
		}
	}
	i := &schema.Index{
		Name:   spec.Name,
		Unique: spec.Unique,
		Table:  parent,
		Parts:  parts,
	}
	if err := convertCommentFromSpec(spec, &i.Attrs); err != nil {
		return nil, err
	}
	return i, nil
}

// Check converts a sqlspec.Check to a schema.Check.
func Check(spec *sqlspec.Check) (*schema.Check, error) {
	return &schema.Check{
		Name: spec.Name,
		Expr: spec.Expr,
	}, nil
}

// PrimaryKey converts a sqlspec.PrimaryKey to a schema.Index.
func PrimaryKey(spec *sqlspec.PrimaryKey, parent *schema.Table) (*schema.Index, error) {
	parts := make([]*schema.IndexPart, 0, len(spec.Columns))
	for seqno, c := range spec.Columns {
		c, err := ColumnByRef(parent, c)
		if err != nil {
			return nil, nil
		}
		parts = append(parts, &schema.IndexPart{
			SeqNo: seqno,
			C:     c,
		})
	}
	return &schema.Index{
		Table: parent,
		Parts: parts,
	}, nil
}

// linkForeignKeys creates the foreign keys defined in the Table's spec by creating references
// to column in the provided Schema. It is assumed that all tables referenced FK definitions in the spec
// are reachable from the provided schema or its connected realm.
func linkForeignKeys(tbl *schema.Table, sch *schema.Schema, table *sqlspec.Table) error {
	for _, spec := range table.ForeignKeys {
		fk := &schema.ForeignKey{Symbol: spec.Symbol, Table: tbl}
		if spec.OnUpdate != nil {
			fk.OnUpdate = schema.ReferenceOption(FromVar(spec.OnUpdate.V))
		}
		if spec.OnDelete != nil {
			fk.OnDelete = schema.ReferenceOption(FromVar(spec.OnDelete.V))
		}
		if n, m := len(spec.Columns), len(spec.RefColumns); n != m {
			return fmt.Errorf("sqlspec: number of referencing and referenced columns do not match for foreign-key %q", fk.Symbol)
		}
		for _, ref := range spec.Columns {
			c, err := ColumnByRef(tbl, ref)
			if err != nil {
				return err
			}
			fk.Columns = append(fk.Columns, c)
		}
		for i, ref := range spec.RefColumns {
			t, c, err := externalRef(ref, sch)
			if isLocalRef(ref) {
				t = fk.Table
				c, err = ColumnByRef(fk.Table, ref)
			}
			if err != nil {
				return err
			}
			if i > 0 && fk.RefTable != t {
				return fmt.Errorf("sqlspec: more than 1 table was referenced for foreign-key %q", fk.Symbol)
			}
			fk.RefTable = t
			fk.RefColumns = append(fk.RefColumns, c)
		}
		tbl.ForeignKeys = append(tbl.ForeignKeys, fk)
	}
	return nil
}

// FromSchema converts a schema.Schema into sqlspec.Schema and []sqlspec.Table.
func FromSchema(s *schema.Schema, fn TableSpecFunc) (*sqlspec.Schema, []*sqlspec.Table, error) {
	spec := &sqlspec.Schema{
		Name: s.Name,
	}
	tables := make([]*sqlspec.Table, 0, len(s.Tables))
	for _, t := range s.Tables {
		table, err := fn(t)
		if err != nil {
			return nil, nil, err
		}
		if s.Name != "" {
			table.Schema = SchemaRef(s.Name)
		}
		tables = append(tables, table)
	}
	return spec, tables, nil
}

// FromTable converts a schema.Table to a sqlspec.Table.
func FromTable(t *schema.Table, colFn ColumnSpecFunc, pkFn PrimaryKeySpecFunc, idxFn IndexSpecFunc,
	fkFn ForeignKeySpecFunc, ckFn CheckSpecFunc) (*sqlspec.Table, error) {
	spec := &sqlspec.Table{
		Name: t.Name,
	}
	for _, c := range t.Columns {
		col, err := colFn(c, t)
		if err != nil {
			return nil, err
		}
		spec.Columns = append(spec.Columns, col)
	}
	if t.PrimaryKey != nil {
		pk, err := pkFn(t.PrimaryKey)
		if err != nil {
			return nil, err
		}
		spec.PrimaryKey = pk
	}
	for _, idx := range t.Indexes {
		i, err := idxFn(idx)
		if err != nil {
			return nil, err
		}
		spec.Indexes = append(spec.Indexes, i)
	}
	for _, fk := range t.ForeignKeys {
		f, err := fkFn(fk)
		if err != nil {
			return nil, err
		}
		spec.ForeignKeys = append(spec.ForeignKeys, f)
	}
	for _, attr := range t.Attrs {
		if c, ok := attr.(*schema.Check); ok {
			spec.Checks = append(spec.Checks, ckFn(c))
		}
	}
	convertCommentFromSchema(t.Attrs, &spec.Extra.Attrs)
	return spec, nil
}

// FromPrimaryKey converts schema.Index to a sqlspec.PrimaryKey.
func FromPrimaryKey(s *schema.Index) (*sqlspec.PrimaryKey, error) {
	c := make([]*schemahcl.Ref, 0, len(s.Parts))
	for _, v := range s.Parts {
		c = append(c, ColumnRef(v.C.Name))
	}
	return &sqlspec.PrimaryKey{
		Columns: c,
	}, nil
}

// FromColumn converts a *schema.Column into a *sqlspec.Column using the ColumnTypeSpecFunc.
func FromColumn(col *schema.Column, columnTypeSpec ColumnTypeSpecFunc) (*sqlspec.Column, error) {
	ct, err := columnTypeSpec(col.Type.Type)
	if err != nil {
		return nil, err
	}
	spec := &sqlspec.Column{
		Name: col.Name,
		Type: ct.Type,
		Null: col.Type.Null,
		DefaultExtension: schemahcl.DefaultExtension{
			Extra: schemahcl.Resource{Attrs: ct.DefaultExtension.Extra.Attrs},
		},
	}
	if col.Default != nil {
		lv, err := toValue(col.Default)
		if err != nil {
			return nil, err
		}
		spec.Default = lv
	}
	convertCommentFromSchema(col.Attrs, &spec.Extra.Attrs)
	return spec, nil
}

// FromGenExpr returns the spec for a generated expression.
func FromGenExpr(x schema.GeneratedExpr, t func(string) string) *schemahcl.Resource {
	return &schemahcl.Resource{
		Type: "as",
		Attrs: []*schemahcl.Attr{
			StrAttr("expr", x.Expr),
			VarAttr("type", t(x.Type)),
		},
	}
}

// ConvertGenExpr converts the "as" attribute or the block under the given resource.
func ConvertGenExpr(r *schemahcl.Resource, c *schema.Column, t func(string) string) error {
	asA, okA := r.Attr("as")
	asR, okR := r.Resource("as")
	switch {
	case okA && okR:
		return fmt.Errorf("multiple as definitions for column %q", c.Name)
	case okA:
		expr, err := asA.String()
		if err != nil {
			return err
		}
		c.Attrs = append(c.Attrs, &schema.GeneratedExpr{
			Type: t(""), // default type.
			Expr: expr,
		})
	case okR:
		var spec struct {
			Expr string `spec:"expr"`
			Type string `spec:"type"`
		}
		if err := asR.As(&spec); err != nil {
			return err
		}
		c.Attrs = append(c.Attrs, &schema.GeneratedExpr{
			Expr: spec.Expr,
			Type: t(spec.Type),
		})
	}
	return nil
}

func toValue(expr schema.Expr) (schemahcl.Value, error) {
	var (
		v   string
		err error
	)
	switch expr := expr.(type) {
	case *schema.RawExpr:
		return &schemahcl.RawExpr{X: expr.X}, nil
	case *schema.Literal:
		v, err = normalizeQuotes(expr.V)
		if err != nil {
			return nil, err
		}
		return &schemahcl.LiteralValue{V: v}, nil
	default:
		return nil, fmt.Errorf("converting expr %T to literal value", expr)
	}
}

func normalizeQuotes(s string) (string, error) {
	if len(s) < 2 {
		return s, nil
	}
	// If string is quoted with single quotes:
	if strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`) {
		uq := strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		return strconv.Quote(uq), nil
	}
	return s, nil
}

// FromIndex converts schema.Index to sqlspec.Index.
func FromIndex(idx *schema.Index, partFns ...func(*schema.IndexPart, *sqlspec.IndexPart)) (*sqlspec.Index, error) {
	spec := &sqlspec.Index{Name: idx.Name, Unique: idx.Unique}
	convertCommentFromSchema(idx.Attrs, &spec.Extra.Attrs)
	if parts, ok := columnsOnly(idx); ok {
		spec.Columns = parts
		return spec, nil
	}
	spec.Parts = make([]*sqlspec.IndexPart, len(idx.Parts))
	for i, p := range idx.Parts {
		part := &sqlspec.IndexPart{Desc: p.Desc}
		switch {
		case p.C == nil && p.X == nil:
			return nil, fmt.Errorf("missing column or expression for key part of index %q", idx.Name)
		case p.C != nil && p.X != nil:
			return nil, fmt.Errorf("multiple key part definitions for index %q", idx.Name)
		case p.C != nil:
			part.Column = ColumnRef(p.C.Name)
		case p.X != nil:
			x, ok := p.X.(*schema.RawExpr)
			if !ok {
				return nil, fmt.Errorf("unexpected expression %T for index %q", p.X, idx.Name)
			}
			part.Expr = x.X
		}
		for _, f := range partFns {
			f(p, part)
		}
		spec.Parts[i] = part
	}
	return spec, nil
}

func columnsOnly(idx *schema.Index) ([]*schemahcl.Ref, bool) {
	parts := make([]*schemahcl.Ref, len(idx.Parts))
	for i, p := range idx.Parts {
		if p.C == nil || p.Desc {
			return nil, false
		}
		parts[i] = ColumnRef(p.C.Name)
	}
	return parts, true
}

// FromForeignKey converts schema.ForeignKey to sqlspec.ForeignKey.
func FromForeignKey(s *schema.ForeignKey) (*sqlspec.ForeignKey, error) {
	c := make([]*schemahcl.Ref, 0, len(s.Columns))
	for _, v := range s.Columns {
		c = append(c, ColumnRef(v.Name))
	}
	r := make([]*schemahcl.Ref, 0, len(s.RefColumns))
	for _, v := range s.RefColumns {
		ref := ColumnRef(v.Name)
		if s.Table != s.RefTable {
			ref = externalColRef(v.Name, s.RefTable.Name)
		}
		r = append(r, ref)
	}
	fk := &sqlspec.ForeignKey{
		Symbol:     s.Symbol,
		Columns:    c,
		RefColumns: r,
	}
	if s.OnUpdate != "" {
		fk.OnUpdate = &schemahcl.Ref{V: Var(string(s.OnUpdate))}
	}
	if s.OnDelete != "" {
		fk.OnDelete = &schemahcl.Ref{V: Var(string(s.OnDelete))}
	}
	return fk, nil
}

// FromCheck converts schema.Check to sqlspec.Check.
func FromCheck(s *schema.Check) *sqlspec.Check {
	return &sqlspec.Check{
		Name: s.Name,
		Expr: s.Expr,
	}
}

// SchemaName returns the name from a ref to a schema.
func SchemaName(ref *schemahcl.Ref) (string, error) {
	if ref == nil {
		return "", errors.New("missing 'schema' attribute")
	}
	parts := strings.Split(ref.V, ".")
	if len(parts) < 2 || parts[0] != "$schema" {
		return "", errors.New("expected ref format of $schema.name")
	}
	return parts[1], nil
}

// ColumnByRef returns a column from the table by its reference.
func ColumnByRef(t *schema.Table, ref *schemahcl.Ref) (*schema.Column, error) {
	s := strings.Split(ref.V, "$column.")
	if len(s) != 2 {
		return nil, fmt.Errorf("specutil: failed to extract column name from %q", ref)
	}
	c, ok := t.Column(s[1])
	if !ok {
		return nil, fmt.Errorf("specutil: unknown column %q in table %q", s[1], t.Name)
	}
	return c, nil
}

func externalRef(ref *schemahcl.Ref, sch *schema.Schema) (*schema.Table, *schema.Column, error) {
	tbl, err := findTable(ref, sch)
	if err != nil {
		return nil, nil, err
	}
	c, err := ColumnByRef(tbl, ref)
	if err != nil {
		return nil, nil, err
	}
	return tbl, c, nil
}

// findTable finds the table referenced by ref in the provided schema. If the table
// is not in the provided schema.Schema other schemas in the connected schema.Realm
// are searched as well.
func findTable(ref *schemahcl.Ref, sch *schema.Schema) (*schema.Table, error) {
	qualifier, tblName, err := tableName(ref)
	if err != nil {
		return nil, err
	}
	// Search the same schema.
	if qualifier == "" || qualifier == sch.Name {
		tbl, ok := sch.Table(tblName)
		if !ok {
			return tbl, fmt.Errorf("sqlspec: table %q not found", tblName)
		}
		return tbl, nil
	}
	if sch.Realm == nil {
		return nil, fmt.Errorf("sqlspec: table %s.%s not found", qualifier, tblName)
	}
	// Search for the table in another schemas in the realm.
	sch, ok := sch.Realm.Schema(qualifier)
	if !ok {
		return nil, fmt.Errorf("sqlspec: schema %q not found", qualifier)
	}
	tbl, ok := sch.Table(tblName)
	if !ok {
		return tbl, fmt.Errorf("sqlspec: table %q not found", tblName)
	}
	return tbl, nil
}

func tableName(ref *schemahcl.Ref) (qualifier, name string, err error) {
	s := strings.Split(ref.V, "$column.")
	if len(s) != 2 {
		return "", "", fmt.Errorf("sqlspec: failed to split by column name from %q", ref)
	}
	table := strings.TrimSuffix(s[0], ".")
	s = strings.Split(table, ".")
	switch len(s) {
	case 2:
		name = s[1]
	case 3:
		qualifier, name = s[1], s[2]
	default:
		return "", "", fmt.Errorf("sqlspec: failed to extract table name from %q", s)
	}
	return
}

func isLocalRef(r *schemahcl.Ref) bool {
	return strings.HasPrefix(r.V, "$column")
}

// ColumnRef returns the reference of a column by its name.
func ColumnRef(cName string) *schemahcl.Ref {
	return &schemahcl.Ref{V: "$column." + cName}
}

func externalColRef(cName string, tName string) *schemahcl.Ref {
	return &schemahcl.Ref{V: "$table." + tName + ".$column." + cName}
}

func qualifiedExternalColRef(cName, tName, sName string) *schemahcl.Ref {
	return &schemahcl.Ref{V: "$table." + sName + "." + tName + ".$column." + cName}
}

// SchemaRef returns the schemahcl.Ref to the schema with the given name.
func SchemaRef(n string) *schemahcl.Ref {
	return &schemahcl.Ref{V: "$schema." + n}
}

// Attrer is the interface that wraps the Attr method.
type Attrer interface {
	Attr(string) (*schemahcl.Attr, bool)
}

// convertCommentFromSpec converts a spec comment attribute to a schema element attribute.
func convertCommentFromSpec(spec Attrer, attrs *[]schema.Attr) error {
	if c, ok := spec.Attr("comment"); ok {
		s, err := c.String()
		if err != nil {
			return err
		}
		*attrs = append(*attrs, &schema.Comment{Text: s})
	}
	return nil
}

// convertCommentFromSchema converts a schema element comment attribute to a spec comment attribute.
func convertCommentFromSchema(src []schema.Attr, trgt *[]*schemahcl.Attr) {
	var c schema.Comment
	if sqlx.Has(src, &c) {
		*trgt = append(*trgt, StrAttr("comment", c.Text))
	}
}

// ReferenceVars holds the HCL variables
// for foreign keys' referential-actions.
var ReferenceVars = []string{
	Var(string(schema.NoAction)),
	Var(string(schema.Restrict)),
	Var(string(schema.Cascade)),
	Var(string(schema.SetNull)),
	Var(string(schema.SetDefault)),
}

// Var formats a string as variable to make it HCL compatible.
// The result is simple, replace each space with underscore.
func Var(s string) string { return strings.ReplaceAll(s, " ", "_") }

// FromVar is the inverse function of Var.
func FromVar(s string) string { return strings.ReplaceAll(s, "_", " ") }
