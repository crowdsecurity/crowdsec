// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package schema

import (
	"context"
	"database/sql"
	"errors"
)

// A NotExistError wraps another error to retain its original text
// but makes it possible to the migrator to catch it.
type NotExistError struct {
	Err error
}

func (e NotExistError) Error() string { return e.Err.Error() }

// IsNotExistError reports if an error is a NotExistError.
func IsNotExistError(err error) bool {
	if err == nil {
		return false
	}
	var e *NotExistError
	return errors.As(err, &e)
}

// ExecQuerier wraps the two standard sql.DB methods.
type ExecQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// An InspectMode controls the amount and depth of information returned on inspection.
type InspectMode uint

const (
	// InspectSchemas enables schema inspection.
	InspectSchemas InspectMode = 1 << iota

	// InspectTables enables schema tables inspection including
	// all its child resources (e.g. columns or indexes).
	InspectTables
)

// Is reports whether the given mode is enabled.
func (m InspectMode) Is(i InspectMode) bool { return m&i != 0 }

type (
	// InspectOptions describes options for Inspector.
	InspectOptions struct {
		// Mode defines the amount of information returned by InspectSchema.
		// If zero, InspectSchema inspects whole resources in the schema.
		Mode InspectMode

		// Tables to inspect. Empty means all tables in the schema.
		Tables []string

		// Exclude defines a list of glob patterns used to filter resources from inspection.
		// The syntax used by the different drivers is implemented as follows:
		//
		//	t   // exclude table 't'.
		//	*   // exclude all tables.
		//	t.c // exclude column, index and foreign-key named 'c' in table 't'.
		//	t.* // the last item defines the filtering; all resources under 't' are excluded.
		//	*.c // the last item defines the filtering; all resourced named 'c' are excluded in all tables.
		//	*.* // the last item defines the filtering; all resourced under all tables are excluded.
		//
		Exclude []string
	}

	// InspectRealmOption describes options for RealmInspector.
	InspectRealmOption struct {
		// Mode defines the amount of information returned by InspectRealm.
		// If zero, InspectRealm inspects all schemas and their child resources.
		Mode InspectMode

		// Schemas to inspect. Empty means all schemas in the realm.
		Schemas []string

		// Exclude defines a list of glob patterns used to filter resources from inspection.
		// The syntax used by the different drivers is implemented as follows:
		//
		//	s     // exclude schema 't'.
		//	*     // exclude all schemas.
		//	s.t   // exclude table 't' under schema 's'.
		//	s.*   // the last item defines the filtering; all tables under 's' are excluded.
		//	*.t   // the last item defines the filtering; all tables named 't' are excluded in all schemas.
		//	*.*   // the last item defines the filtering; all tables under all schemas are excluded.
		//	*.*.c // the last item defines the filtering; all resourced named 'c' are excluded in all tables.
		//	*.*.* // the last item defines the filtering; all resources are excluded in all tables.
		//
		Exclude []string
	}

	// Inspector is the interface implemented by the different database
	// drivers for inspecting schema or databases.
	Inspector interface {
		// InspectSchema returns the schema description by its name. An empty name means the
		// "attached schema" (e.g. SCHEMA() in MySQL or CURRENT_SCHEMA() in PostgreSQL).
		// A NotExistError error is returned if the schema does not exist in the database.
		InspectSchema(ctx context.Context, name string, opts *InspectOptions) (*Schema, error)

		// InspectRealm returns the description of the connected database.
		InspectRealm(ctx context.Context, opts *InspectRealmOption) (*Realm, error)
	}
)

// Normalizer is the interface implemented by the different database drivers for
// "normalizing" schema objects. i.e. converting schema objects defined in natural
// form to their representation in the database. Thus, two schema objects are equal
// if their normal forms are equal.
type Normalizer interface {
	// NormalizeSchema returns the normal representation of a schema.
	NormalizeSchema(context.Context, *Schema) (*Schema, error)

	// NormalizeRealm returns the normal representation of a database.
	NormalizeRealm(context.Context, *Realm) (*Realm, error)
}
