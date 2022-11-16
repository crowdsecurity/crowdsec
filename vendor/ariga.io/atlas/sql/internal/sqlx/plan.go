// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlx

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"

	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/schema"
)

type execPlanner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PlanChanges(context.Context, string, []schema.Change, ...migrate.PlanOption) (*migrate.Plan, error)
}

// ApplyChanges is a helper used by the different drivers to apply changes.
func ApplyChanges(ctx context.Context, changes []schema.Change, p execPlanner, opts ...migrate.PlanOption) error {
	plan, err := p.PlanChanges(ctx, "apply", changes, opts...)
	if err != nil {
		return err
	}
	for _, c := range plan.Changes {
		if _, err := p.ExecContext(ctx, c.Cmd, c.Args...); err != nil {
			if c.Comment != "" {
				err = fmt.Errorf("%s: %w", c.Comment, err)
			}
			return err
		}
	}
	return nil
}

// DetachCycles takes a list of schema changes, and detaches
// references between changes if there is at least one circular
// reference in the changeset. More explicitly, it postpones fks
// creation, or deletes fks before deletes their tables.
func DetachCycles(changes []schema.Change) ([]schema.Change, error) {
	sorted, err := sortMap(changes)
	if err == errCycle {
		return detachReferences(changes), nil
	}
	if err != nil {
		return nil, err
	}
	planned := make([]schema.Change, len(changes))
	copy(planned, changes)
	sort.Slice(planned, func(i, j int) bool {
		return sorted[table(planned[i])] < sorted[table(planned[j])]
	})
	return planned, nil
}

// detachReferences detaches all table references.
func detachReferences(changes []schema.Change) []schema.Change {
	var planned, deferred []schema.Change
	for _, change := range changes {
		switch change := change.(type) {
		case *schema.AddTable:
			var (
				ext  []schema.Change
				self []*schema.ForeignKey
			)
			for _, fk := range change.T.ForeignKeys {
				if fk.RefTable == change.T {
					self = append(self, fk)
				} else {
					ext = append(ext, &schema.AddForeignKey{F: fk})
				}
			}
			if len(ext) > 0 {
				deferred = append(deferred, &schema.ModifyTable{T: change.T, Changes: ext})
				t := *change.T
				t.ForeignKeys = self
				change = &schema.AddTable{T: &t, Extra: change.Extra}
			}
			planned = append(planned, change)
		case *schema.DropTable:
			var fks []schema.Change
			for _, fk := range change.T.ForeignKeys {
				if fk.RefTable != change.T {
					fks = append(fks, &schema.DropForeignKey{F: fk})
				}
			}
			if len(fks) > 0 {
				planned = append(planned, &schema.ModifyTable{T: change.T, Changes: fks})
				t := *change.T
				t.ForeignKeys = nil
				change = &schema.DropTable{T: &t, Extra: change.Extra}
			}
			deferred = append(deferred, change)
		case *schema.ModifyTable:
			var fks, rest []schema.Change
			for _, c := range change.Changes {
				switch c := c.(type) {
				case *schema.AddForeignKey:
					fks = append(fks, c)
				default:
					rest = append(rest, c)
				}
			}
			if len(fks) > 0 {
				deferred = append(deferred, &schema.ModifyTable{T: change.T, Changes: fks})
			}
			if len(rest) > 0 {
				planned = append(planned, &schema.ModifyTable{T: change.T, Changes: rest})
			}
		default:
			planned = append(planned, change)
		}
	}
	return append(planned, deferred...)
}

// errCycle is an internal error to indicate a case of a cycle.
var errCycle = errors.New("cycle detected")

// sortMap returns an index-map indicates the position of table in a topological
// sort in reversed order based on its references, and a boolean indicate if there
// is a non-self loop.
func sortMap(changes []schema.Change) (map[string]int, error) {
	var (
		visit     func(string) bool
		sorted    = make(map[string]int)
		progress  = make(map[string]bool)
		deps, err = dependencies(changes)
	)
	if err != nil {
		return nil, err
	}
	visit = func(name string) bool {
		if _, done := sorted[name]; done {
			return false
		}
		if progress[name] {
			return true
		}
		progress[name] = true
		for _, ref := range deps[name] {
			if visit(ref.Name) {
				return true
			}
		}
		delete(progress, name)
		sorted[name] = len(sorted)
		return false
	}
	for node := range deps {
		if visit(node) {
			return nil, errCycle
		}
	}
	return sorted, nil
}

// dependencies returned an adjacency list of all tables and the table they depend on
func dependencies(changes []schema.Change) (map[string][]*schema.Table, error) {
	deps := make(map[string][]*schema.Table)
	for _, change := range changes {
		switch change := change.(type) {
		case *schema.AddTable:
			for _, fk := range change.T.ForeignKeys {
				if err := checkFK(fk); err != nil {
					return nil, err
				}
				if fk.RefTable != change.T {
					deps[change.T.Name] = append(deps[change.T.Name], fk.RefTable)
				}
			}
		case *schema.DropTable:
			for _, fk := range change.T.ForeignKeys {
				if err := checkFK(fk); err != nil {
					return nil, err
				}
				if isDropped(changes, fk.RefTable) {
					deps[fk.RefTable.Name] = append(deps[fk.RefTable.Name], fk.Table)
				}
			}
		case *schema.ModifyTable:
			for _, c := range change.Changes {
				switch c := c.(type) {
				case *schema.AddForeignKey:
					if err := checkFK(c.F); err != nil {
						return nil, err
					}
					if c.F.RefTable != change.T {
						deps[change.T.Name] = append(deps[change.T.Name], c.F.RefTable)
					}
				case *schema.ModifyForeignKey:
					if err := checkFK(c.To); err != nil {
						return nil, err
					}
					if c.To.RefTable != change.T {
						deps[change.T.Name] = append(deps[change.T.Name], c.To.RefTable)
					}
				}
			}
		}
	}
	return deps, nil
}

func checkFK(fk *schema.ForeignKey) error {
	var cause []string
	if fk.Table == nil {
		cause = append(cause, "child table")
	}
	if len(fk.Columns) == 0 {
		cause = append(cause, "child columns")
	}
	if fk.RefTable == nil {
		cause = append(cause, "parent table")
	}
	if len(fk.RefColumns) == 0 {
		cause = append(cause, "parent columns")
	}
	if len(cause) != 0 {
		return fmt.Errorf("missing %q for foreign key: %q", cause, fk.Symbol)
	}
	return nil
}

// table extracts a table from the given change.
func table(change schema.Change) (t string) {
	switch change := change.(type) {
	case *schema.AddTable:
		t = change.T.Name
	case *schema.DropTable:
		t = change.T.Name
	case *schema.ModifyTable:
		t = change.T.Name
	}
	return
}

// isDropped checks if the given table is marked as a deleted in the changeset.
func isDropped(changes []schema.Change, t *schema.Table) bool {
	for _, c := range changes {
		if c, ok := c.(*schema.DropTable); ok && c.T.Name == t.Name {
			return true
		}
	}
	return false
}

// CheckChangesScope checks that changes can be applied
// on a schema scope (connection).
func CheckChangesScope(changes []schema.Change) error {
	names := make(map[string]struct{})
	for _, c := range changes {
		var t *schema.Table
		switch c := c.(type) {
		case *schema.AddSchema, *schema.ModifySchema, *schema.DropSchema:
			return fmt.Errorf("%T is not allowed when migration plan is scoped to one schema", c)
		case *schema.AddTable:
			t = c.T
		case *schema.ModifyTable:
			t = c.T
		case *schema.DropTable:
			t = c.T
		default:
			continue
		}
		if t.Schema != nil && t.Schema.Name != "" {
			names[t.Schema.Name] = struct{}{}
		}
		for _, c := range t.Columns {
			e, ok := c.Type.Type.(*schema.EnumType)
			if ok && e.Schema != nil && e.Schema.Name != "" {
				names[t.Schema.Name] = struct{}{}
			}
		}
	}
	if len(names) > 1 {
		return fmt.Errorf("found %d schemas when migration plan is scoped to one", len(names))
	}
	return nil
}
