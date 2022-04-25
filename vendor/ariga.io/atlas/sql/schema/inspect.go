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
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

type (
	// InspectOptions describes options for Inspector.
	InspectOptions struct {
		// Tables to inspect. Empty means all tables in the schema.
		Tables []string
	}

	// InspectTableOptions describes options for TableInspector.
	InspectTableOptions struct {
		// Schema defines an optional schema to inspect.
		Schema string
	}

	// InspectRealmOption describes options for RealmInspector.
	InspectRealmOption struct {
		// Schemas to inspect. Empty means all tables in the schema.
		Schemas []string
	}

	// Inspector is the interface implemented by the different database
	// drivers for inspecting schema or databases.
	Inspector interface {
		// InspectSchema returns the schema description by its name. An empty name means the
		// "attached schema" (e.g. SCHEMA() in MySQL or CURRENT_SCHEMA() in PostgreSQL).
		// A NotExistError error is returned if the schema does not exists in the database.
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
