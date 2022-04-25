package sqlspec

import (
	"ariga.io/atlas/schema/schemaspec"
)

type (

	// Schema holds a specification for a Schema.
	Schema struct {
		Name string `spec:",name"`
		schemaspec.DefaultExtension
	}

	// Table holds a specification for an SQL table.
	Table struct {
		Name        string          `spec:",name"`
		Schema      *schemaspec.Ref `spec:"schema"`
		Columns     []*Column       `spec:"column"`
		PrimaryKey  *PrimaryKey     `spec:"primary_key"`
		ForeignKeys []*ForeignKey   `spec:"foreign_key"`
		Indexes     []*Index        `spec:"index"`
		Checks      []*Check        `spec:"check"`
		schemaspec.DefaultExtension
	}

	// Column holds a specification for a column in an SQL table.
	Column struct {
		Name    string           `spec:",name"`
		Null    bool             `spec:"null"`
		Type    *schemaspec.Type `spec:"type"`
		Default schemaspec.Value `spec:"default"`
		schemaspec.DefaultExtension
	}

	// PrimaryKey holds a specification for the primary key of a table.
	PrimaryKey struct {
		Columns []*schemaspec.Ref `spec:"columns"`
		schemaspec.DefaultExtension
	}

	// Index holds a specification for the index key of a table.
	Index struct {
		Name    string            `spec:",name"`
		Unique  bool              `spec:"unique,omitempty"`
		Parts   []*IndexPart      `spec:"on"`
		Columns []*schemaspec.Ref `spec:"columns"`
		schemaspec.DefaultExtension
	}

	// IndexPart holds a specification for the index key part.
	IndexPart struct {
		Desc   bool            `spec:"desc,omitempty"`
		Column *schemaspec.Ref `spec:"column"`
		Expr   string          `spec:"expr,omitempty"`
		schemaspec.DefaultExtension
	}

	// Check holds a specification for a check constraint on a table.
	Check struct {
		Name string `spec:",name"`
		Expr string `spec:"expr"`
		schemaspec.DefaultExtension
	}

	// ForeignKey holds a specification for the Foreign key of a table.
	ForeignKey struct {
		Symbol     string            `spec:",name"`
		Columns    []*schemaspec.Ref `spec:"columns"`
		RefColumns []*schemaspec.Ref `spec:"ref_columns"`
		OnUpdate   *schemaspec.Ref   `spec:"on_update"`
		OnDelete   *schemaspec.Ref   `spec:"on_delete"`
		schemaspec.DefaultExtension
	}

	// Type represents a database agnostic column type.
	Type string
)

func init() {
	schemaspec.Register("table", &Table{})
	schemaspec.Register("schema", &Schema{})
}
