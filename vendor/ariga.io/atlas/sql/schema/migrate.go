// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schema

type (
	// A Change represents a schema change. The types below implement this
	// interface and can be used for describing schema changes.
	//
	// The Change interface can also be implemented outside this package
	// as follows:
	//
	//	type RenameType struct {
	//		schema.Change
	//		From, To string
	//	}
	//
	//	var t schema.Change = &RenameType{From: "old", To: "new"}
	//
	Change interface {
		change()
	}

	// Clause carries additional information that can be added
	// to schema changes. The Clause interface can be implemented
	// outside this package as follows:
	//
	//	type Authorization struct {
	//		schema.Clause
	//		UserName string
	//	}
	//
	//	var c schema.Clause = &Authorization{UserName: "a8m"}
	//
	Clause interface {
		clause()
	}

	// AddSchema describes a schema (named database) creation change.
	// Unlike table creation, schemas and their elements are described
	// with separate changes. For example, "AddSchema" and "AddTable"
	AddSchema struct {
		S     *Schema
		Extra []Clause // Extra clauses and options.
	}

	// DropSchema describes a schema (named database) removal change.
	DropSchema struct {
		S     *Schema
		Extra []Clause // Extra clauses and options.
	}

	// ModifySchema describes a modification change for schema attributes.
	ModifySchema struct {
		S       *Schema
		Changes []Change
	}

	// AddTable describes a table creation change.
	AddTable struct {
		T     *Table
		Extra []Clause // Extra clauses and options.
	}

	// DropTable describes a table removal change.
	DropTable struct {
		T     *Table
		Extra []Clause // Extra clauses.
	}

	// ModifyTable describes a table modification change.
	ModifyTable struct {
		T       *Table
		Changes []Change
	}

	// AddColumn describes a column creation change.
	AddColumn struct {
		C *Column
	}

	// DropColumn describes a column removal change.
	DropColumn struct {
		C *Column
	}

	// ModifyColumn describes a change that modifies a column.
	ModifyColumn struct {
		From, To *Column
		Change   ChangeKind
	}

	// AddIndex describes an index creation change.
	AddIndex struct {
		I *Index
	}

	// DropIndex describes an index removal change.
	DropIndex struct {
		I *Index
	}

	// ModifyIndex describes an index modification.
	ModifyIndex struct {
		From, To *Index
		Change   ChangeKind
	}

	// AddForeignKey describes a foreign-key creation change.
	AddForeignKey struct {
		F *ForeignKey
	}

	// DropForeignKey describes a foreign-key removal change.
	DropForeignKey struct {
		F *ForeignKey
	}

	// ModifyForeignKey describes a change that modifies a foreign-key.
	ModifyForeignKey struct {
		From, To *ForeignKey
		Change   ChangeKind
	}

	// AddCheck describes a CHECK constraint creation change.
	AddCheck struct {
		C *Check
	}

	// DropCheck describes a CHECK constraint removal change.
	DropCheck struct {
		C *Check
	}

	// ModifyCheck describes a change that modifies a check.
	ModifyCheck struct {
		From, To *Check
		Change   ChangeKind
	}

	// AddAttr describes an attribute addition.
	AddAttr struct {
		A Attr
	}

	// DropAttr describes an attribute removal.
	DropAttr struct {
		A Attr
	}

	// ModifyAttr describes a change that modifies an element attribute.
	ModifyAttr struct {
		From, To Attr
	}

	// IfExists represents a clause in a schema change that is commonly
	// supported by multiple statements (e.g. DROP TABLE or DROP SCHEMA).
	IfExists struct{}

	// IfNotExists represents a clause in a schema change that is commonly
	// supported by multiple statements (e.g. CREATE TABLE or CREATE SCHEMA).
	IfNotExists struct{}
)

// A ChangeKind describes a change kind that can be combined
// using a set of flags. The zero kind is no change.
type ChangeKind uint

const (
	// NoChange holds the zero value of a change kind.
	NoChange ChangeKind = 0

	// Common changes.

	// ChangeAttr describes attributes change of an element.
	// For example, a table CHECK was added or changed.
	ChangeAttr ChangeKind = 1 << (iota - 1)
	// ChangeCharset describes character-set change.
	ChangeCharset
	// ChangeCollation describes collation/encoding change.
	ChangeCollation
	// ChangeComment describes comment chang (of any element).
	ChangeComment

	// Column specific changes.

	// ChangeNull describe a change to the NULL constraint.
	ChangeNull
	// ChangeType describe a column type change.
	ChangeType
	// ChangeDefault describe a column default change.
	ChangeDefault

	// Index specific changes.

	// ChangeUnique describes a change to the uniqueness constraint.
	// For example, an index was changed from non-unique to unique.
	ChangeUnique
	// ChangeParts describes a change to one or more of the index parts.
	// For example, index keeps its previous name, but the columns order
	// was changed.
	ChangeParts

	// Foreign key specific changes.

	// ChangeColumn describes a change to the foreign-key (child) columns.
	ChangeColumn
	// ChangeRefColumn describes a change to the foreign-key (parent) columns.
	ChangeRefColumn
	// ChangeRefTable describes a change to the foreign-key (parent) table.
	ChangeRefTable
	// ChangeUpdateAction describes a change to the foreign-key update action.
	ChangeUpdateAction
	// ChangeDeleteAction describes a change to the foreign-key delete action.
	ChangeDeleteAction
)

// Is reports whether c is match the given change kind.
func (k ChangeKind) Is(c ChangeKind) bool {
	return k == c || k&c != 0
}

// Differ is the interface implemented by the different
// drivers for comparing and diffing schema top elements.
type Differ interface {
	// RealmDiff returns a diff report for migrating a realm
	// (or a database) from state "from" to state "to". An error
	// is returned if such step is not possible.
	RealmDiff(from, to *Realm) ([]Change, error)

	// SchemaDiff returns a diff report for migrating a schema
	// from state "from" to state "to". An error is returned
	// if such step is not possible.
	SchemaDiff(from, to *Schema) ([]Change, error)

	// TableDiff returns a diff report for migrating a table
	// from state "from" to state "to". An error is returned
	// if such step is not possible.
	TableDiff(from, to *Table) ([]Change, error)
}

// changes.
func (*AddAttr) change()          {}
func (*DropAttr) change()         {}
func (*ModifyAttr) change()       {}
func (*AddSchema) change()        {}
func (*DropSchema) change()       {}
func (*ModifySchema) change()     {}
func (*AddTable) change()         {}
func (*DropTable) change()        {}
func (*ModifyTable) change()      {}
func (*AddIndex) change()         {}
func (*DropIndex) change()        {}
func (*ModifyIndex) change()      {}
func (*AddCheck) change()         {}
func (*DropCheck) change()        {}
func (*ModifyCheck) change()      {}
func (*AddColumn) change()        {}
func (*DropColumn) change()       {}
func (*ModifyColumn) change()     {}
func (*AddForeignKey) change()    {}
func (*DropForeignKey) change()   {}
func (*ModifyForeignKey) change() {}

// clauses.
func (*IfExists) clause()    {}
func (*IfNotExists) clause() {}
