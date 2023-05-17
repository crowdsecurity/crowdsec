// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schema

type (
	// A Realm or a database describes a domain of schema resources that are logically connected
	// and can be accessed and queried in the same connection (e.g. a physical database instance).
	Realm struct {
		Schemas []*Schema
		Attrs   []Attr
	}

	// A Schema describes a database schema (i.e. named database).
	Schema struct {
		Name   string
		Realm  *Realm
		Tables []*Table
		Attrs  []Attr // Attrs and options.
	}

	// A Table represents a table definition.
	Table struct {
		Name        string
		Schema      *Schema
		Columns     []*Column
		Indexes     []*Index
		PrimaryKey  *Index
		ForeignKeys []*ForeignKey
		Attrs       []Attr // Attrs, constraints and options.
	}

	// A Column represents a column definition.
	Column struct {
		Name    string
		Type    *ColumnType
		Default Expr
		Attrs   []Attr
		Indexes []*Index
		// Foreign keys that this column is
		// part of their child columns.
		ForeignKeys []*ForeignKey
	}

	// ColumnType represents a column type that is implemented by the dialect.
	ColumnType struct {
		Type Type
		Raw  string
		Null bool
	}

	// An Index represents an index definition.
	Index struct {
		Name   string
		Unique bool
		Table  *Table
		Attrs  []Attr
		Parts  []*IndexPart
	}

	// An IndexPart represents an index part that
	// can be either an expression or a column.
	IndexPart struct {
		// SeqNo represents the sequence number of the key part
		// in the index.
		SeqNo int
		// Desc indicates if the key part is stored in descending
		// order. All databases use ascending order as default.
		Desc  bool
		X     Expr
		C     *Column
		Attrs []Attr
	}

	// A ForeignKey represents an index definition.
	ForeignKey struct {
		Symbol     string
		Table      *Table
		Columns    []*Column
		RefTable   *Table
		RefColumns []*Column
		OnUpdate   ReferenceOption
		OnDelete   ReferenceOption
	}
)

// Schema returns the first schema that matched the given name.
func (r *Realm) Schema(name string) (*Schema, bool) {
	for _, s := range r.Schemas {
		if s.Name == name {
			return s, true
		}
	}
	return nil, false
}

// Table returns the first table that matched the given name.
func (s *Schema) Table(name string) (*Table, bool) {
	for _, t := range s.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return nil, false
}

// Column returns the first column that matched the given name.
func (t *Table) Column(name string) (*Column, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

// Index returns the first index that matched the given name.
func (t *Table) Index(name string) (*Index, bool) {
	for _, i := range t.Indexes {
		if i.Name == name {
			return i, true
		}
	}
	return nil, false
}

// ForeignKey returns the first foreign-key that matched the given symbol (constraint name).
func (t *Table) ForeignKey(symbol string) (*ForeignKey, bool) {
	for _, f := range t.ForeignKeys {
		if f.Symbol == symbol {
			return f, true
		}
	}
	return nil, false
}

// Column returns the first column that matches the given name.
func (f *ForeignKey) Column(name string) (*Column, bool) {
	for _, c := range f.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

// RefColumn returns the first referenced column that matches the given name.
func (f *ForeignKey) RefColumn(name string) (*Column, bool) {
	for _, c := range f.RefColumns {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

// ReferenceOption for constraint actions.
type ReferenceOption string

// Reference options (actions) specified by ON UPDATE and ON DELETE
// subclauses of the FOREIGN KEY clause.
const (
	NoAction   ReferenceOption = "NO ACTION"
	Restrict   ReferenceOption = "RESTRICT"
	Cascade    ReferenceOption = "CASCADE"
	SetNull    ReferenceOption = "SET NULL"
	SetDefault ReferenceOption = "SET DEFAULT"
)

type (
	// A Type represents a database type. The types below implements this
	// interface and can be used for describing schemas.
	//
	// The Type interface can also be implemented outside this package as follows:
	//
	//	type SpatialType struct {
	//		schema.Type
	//		T string
	//	}
	//
	//	var t schema.Type = &SpatialType{T: "point"}
	//
	Type interface {
		typ()
	}

	// EnumType represents an enum type.
	EnumType struct {
		T      string   // Optional type.
		Values []string // Enum values.
		Schema *Schema  // Optional schema.
	}

	// BinaryType represents a type that stores a binary data.
	BinaryType struct {
		T    string
		Size *int
	}

	// StringType represents a string type.
	StringType struct {
		T    string
		Size int
	}

	// BoolType represents a boolean type.
	BoolType struct {
		T string
	}

	// IntegerType represents an int type.
	IntegerType struct {
		T        string
		Unsigned bool
		Attrs    []Attr
	}

	// DecimalType represents a fixed-point type that stores exact numeric values.
	DecimalType struct {
		T         string
		Precision int
		Scale     int
		Unsigned  bool
	}

	// FloatType represents a floating-point type that stores approximate numeric values.
	FloatType struct {
		T         string
		Unsigned  bool
		Precision int
	}

	// TimeType represents a date/time type.
	TimeType struct {
		T         string
		Precision *int
	}

	// JSONType represents a JSON type.
	JSONType struct {
		T string
	}

	// SpatialType represents a spatial/geometric type.
	SpatialType struct {
		T string
	}

	// UnsupportedType represents a type that is not supported by the drivers.
	UnsupportedType struct {
		T string
	}
)

type (
	// Expr defines an SQL expression in schema DDL.
	Expr interface {
		expr()
	}

	// Literal represents a basic literal expression like 1, or '1'.
	// String literals are usually quoted with single or double quotes.
	Literal struct {
		V string
	}

	// RawExpr represents a raw expression like "uuid()" or "current_timestamp()".
	// Unlike literals, raw expression are usually inlined as is on migration.
	RawExpr struct {
		X string
	}
)

type (
	// Attr represents the interface that all attributes implement.
	Attr interface {
		attr()
	}

	// Comment describes a schema element comment.
	Comment struct {
		Text string
	}

	// Charset describes a column or a table character-set setting.
	Charset struct {
		V string
	}

	// Collation describes a column or a table collation setting.
	Collation struct {
		V string
	}

	// Check describes a CHECK constraint.
	Check struct {
		Name  string // Optional constraint name.
		Expr  string // Actual CHECK.
		Attrs []Attr // Additional attributes (e.g. ENFORCED).
	}

	// GeneratedExpr describes the expression used for generating
	// the value of a generated/virtual column.
	GeneratedExpr struct {
		Expr string
		Type string // Optional type. e.g. STORED or VIRTUAL.
	}
)

// expressions.
func (*Literal) expr() {}
func (*RawExpr) expr() {}

// types.
func (*BoolType) typ()        {}
func (*EnumType) typ()        {}
func (*TimeType) typ()        {}
func (*JSONType) typ()        {}
func (*FloatType) typ()       {}
func (*StringType) typ()      {}
func (*BinaryType) typ()      {}
func (*SpatialType) typ()     {}
func (*IntegerType) typ()     {}
func (*DecimalType) typ()     {}
func (*UnsupportedType) typ() {}

// attributes.
func (*Check) attr()         {}
func (*Comment) attr()       {}
func (*Charset) attr()       {}
func (*Collation) attr()     {}
func (*GeneratedExpr) attr() {}
