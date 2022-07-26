// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlite

import (
	"context"
	"fmt"
	"strings"

	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/schema"
)

// A planApply provides migration capabilities for schema elements.
type planApply struct{ conn }

// PlanChanges returns a migration plan for the given schema changes.
func (p *planApply) PlanChanges(ctx context.Context, name string, changes []schema.Change) (*migrate.Plan, error) {
	s := &state{
		conn: p.conn,
		Plan: migrate.Plan{
			Name:          name,
			Reversible:    true,
			Transactional: true,
		},
	}
	if err := s.plan(ctx, changes); err != nil {
		return nil, err
	}
	for _, c := range s.Changes {
		if c.Reverse == "" {
			s.Reversible = false
		}
	}
	return &s.Plan, nil
}

// ApplyChanges applies the changes on the database. An error is returned
// if the driver is unable to produce a plan to it, or one of the statements
// is failed or unsupported.
func (p *planApply) ApplyChanges(ctx context.Context, changes []schema.Change) error {
	return sqlx.ApplyChanges(ctx, changes, p)
}

// state represents the state of a planning. It's not part of
// planApply so that multiple planning/applying can be called
// in parallel.
type state struct {
	conn
	migrate.Plan
	skipFKs bool
}

// Exec executes the changes on the database. An error is returned
// if one of the operations fail, or a change is not supported.
func (s *state) plan(ctx context.Context, changes []schema.Change) (err error) {
	for _, c := range changes {
		switch c := c.(type) {
		case *schema.AddTable:
			err = s.addTable(ctx, c)
		case *schema.DropTable:
			err = s.dropTable(c)
		case *schema.ModifyTable:
			err = s.modifyTable(ctx, c)
		default:
			err = fmt.Errorf("unsupported change %T", c)
		}
		if err != nil {
			return err
		}
	}
	// Disable foreign-keys enforcement if it is required
	// by one of the changes in the plan.
	if s.skipFKs && s.conn.fkEnabled {
		// Callers should note that these 2 pragmas are no-op in transactions,
		// and therefore, should not call BEGIN manually. https://sqlite.org/pragma.html#pragma_foreign_keys
		s.Changes = append([]*migrate.Change{{Cmd: "PRAGMA foreign_keys = off", Comment: "disable the enforcement of foreign-keys constraints"}}, s.Changes...)
		s.append(&migrate.Change{Cmd: "PRAGMA foreign_keys = on", Comment: "enable back the enforcement of foreign-keys constraints"})
	}
	return nil
}

// addTable builds and executes the query for creating a table in a schema.
func (s *state) addTable(ctx context.Context, add *schema.AddTable) error {
	var (
		errs []string
		b    = Build("CREATE TABLE").Ident(add.T.Name)
	)
	if sqlx.Has(add.Extra, &schema.IfNotExists{}) {
		b.P("IF NOT EXISTS")
	}
	b.Wrap(func(b *sqlx.Builder) {
		b.MapComma(add.T.Columns, func(i int, b *sqlx.Builder) {
			if err := s.column(b, add.T.Columns[i]); err != nil {
				errs = append(errs, err.Error())
			}
		})
		// Primary keys with auto-increment are inlined on the column definition.
		if pk := add.T.PrimaryKey; pk != nil && !autoincPK(pk) {
			b.Comma().P("PRIMARY KEY")
			s.indexParts(b, pk.Parts)
		}
		if len(add.T.ForeignKeys) > 0 {
			b.Comma()
			s.fks(b, add.T.ForeignKeys...)
		}
		for _, attr := range add.T.Attrs {
			if c, ok := attr.(*schema.Check); ok {
				b.Comma()
				check(b, c)
			}
		}
	})
	if len(errs) > 0 {
		return fmt.Errorf("create table %q: %s", add.T.Name, strings.Join(errs, ", "))
	}
	if p := (WithoutRowID{}); sqlx.Has(add.T.Attrs, &p) {
		b.P("WITHOUT ROWID")
	}
	s.append(&migrate.Change{
		Cmd:     b.String(),
		Source:  add,
		Reverse: Build("DROP TABLE").Table(add.T).String(),
		Comment: fmt.Sprintf("create %q table", add.T.Name),
	})
	if err := s.tableSeq(ctx, add); err != nil {
		return err
	}
	return s.addIndexes(add.T, add.T.Indexes...)
}

// dropTable builds and executes the query for dropping a table from a schema.
func (s *state) dropTable(drop *schema.DropTable) error {
	s.skipFKs = true
	b := Build("DROP TABLE").Ident(drop.T.Name)
	if sqlx.Has(drop.Extra, &schema.IfExists{}) {
		b.P("IF EXISTS")
	}
	s.append(&migrate.Change{
		Cmd:     b.String(),
		Source:  drop,
		Comment: fmt.Sprintf("drop %q table", drop.T.Name),
	})
	return nil
}

// modifyTable builds and executes the queries for bringing the table into its modified state.
// If the modification contains changes that are not index creation/deletion or a simple column
// addition, the changes are applied using a temporary table following the procedure mentioned
// in: https://www.sqlite.org/lang_altertable.html#making_other_kinds_of_table_schema_changes.
func (s *state) modifyTable(ctx context.Context, modify *schema.ModifyTable) error {
	if alterable(modify) {
		return s.alterTable(modify)
	}
	s.skipFKs = true
	newT := *modify.T
	indexes := newT.Indexes
	newT.Indexes = nil
	newT.Name = "new_" + newT.Name
	// Create a new table with a temporary name, and copy the existing rows to it.
	if err := s.addTable(ctx, &schema.AddTable{T: &newT}); err != nil {
		return err
	}
	if err := s.copyRows(modify.T, &newT, modify.Changes); err != nil {
		return err
	}
	// Drop the current table, and rename the new one to its real name.
	s.append(&migrate.Change{
		Cmd:     Build("DROP TABLE").Ident(modify.T.Name).String(),
		Source:  modify,
		Comment: fmt.Sprintf("drop %q table after copying rows", modify.T.Name),
	})
	s.append(&migrate.Change{
		Cmd:     Build("ALTER TABLE").Ident(newT.Name).P("RENAME TO").Ident(modify.T.Name).String(),
		Source:  modify,
		Comment: fmt.Sprintf("rename temporary table %q to %q", newT.Name, modify.T.Name),
	})
	return s.addIndexes(modify.T, indexes...)
}

func (s *state) column(b *sqlx.Builder, c *schema.Column) error {
	b.Ident(c.Name).P(mustFormat(c.Type.Type))
	if !c.Type.Null {
		b.P("NOT")
	}
	b.P("NULL")
	if c.Default != nil {
		x, err := defaultValue(c)
		if err != nil {
			return err
		}
		b.P("DEFAULT", x)
	}
	if sqlx.Has(c.Attrs, &AutoIncrement{}) {
		b.P("PRIMARY KEY AUTOINCREMENT")
	}
	return nil
}

func (s *state) addIndexes(t *schema.Table, indexes ...*schema.Index) error {
	for _, idx := range indexes {
		// PRIMARY KEY or UNIQUE columns automatically create indexes with the generated name.
		// See: sqlite/build.c#sqlite3CreateIndex. Therefore, we ignore such PKs, but create
		// the inlined UNIQUE constraints manually with custom name, because SQLite does not
		// allow creating indexes with such names manually. Note, this case is possible if
		// "apply" schema that was inspected from the database as-is.
		if strings.HasPrefix(idx.Name, "sqlite_autoindex") {
			if i := (IndexOrigin{}); sqlx.Has(idx.Attrs, &i) && i.O == "p" {
				continue
			}
			// Use the following format: <Table>_<Columns>.
			names := make([]string, len(idx.Parts)+1)
			names[0] = t.Name
			for i, p := range idx.Parts {
				if p.C == nil {
					return fmt.Errorf("unexpected index part %s (%d)", idx.Name, i)
				}
				names[i+1] = p.C.Name
			}
			idx.Name = strings.Join(names, "_")
		}
		b := Build("CREATE")
		if idx.Unique {
			b.P("UNIQUE")
		}
		b.P("INDEX")
		if idx.Name != "" {
			b.Ident(idx.Name)
		}
		b.P("ON").Ident(t.Name)
		s.indexParts(b, idx.Parts)
		if p := (IndexPredicate{}); sqlx.Has(idx.Attrs, &p) {
			b.P("WHERE").P(p.P)
		}
		s.append(&migrate.Change{
			Cmd:     b.String(),
			Source:  &schema.AddIndex{I: idx},
			Reverse: Build("DROP INDEX").Ident(idx.Name).String(),
			Comment: fmt.Sprintf("create index %q to table: %q", idx.Name, t.Name),
		})
	}
	return nil
}

func (s *state) indexParts(b *sqlx.Builder, parts []*schema.IndexPart) {
	b.Wrap(func(b *sqlx.Builder) {
		b.MapComma(parts, func(i int, b *sqlx.Builder) {
			switch part := parts[i]; {
			case part.C != nil:
				b.Ident(part.C.Name)
			case part.X != nil:
				b.WriteString(part.X.(*schema.RawExpr).X)
			}
			if parts[i].Desc {
				b.P("DESC")
			}
		})
	})
}

func (s *state) fks(b *sqlx.Builder, fks ...*schema.ForeignKey) {
	b.MapComma(fks, func(i int, b *sqlx.Builder) {
		fk := fks[i]
		if fk.Symbol != "" {
			b.P("CONSTRAINT").Ident(fk.Symbol)
		}
		b.P("FOREIGN KEY")
		b.Wrap(func(b *sqlx.Builder) {
			b.MapComma(fk.Columns, func(i int, b *sqlx.Builder) {
				b.Ident(fk.Columns[i].Name)
			})
		})
		b.P("REFERENCES").Ident(fk.RefTable.Name)
		b.Wrap(func(b *sqlx.Builder) {
			b.MapComma(fk.RefColumns, func(i int, b *sqlx.Builder) {
				b.Ident(fk.RefColumns[i].Name)
			})
		})
		if fk.OnUpdate != "" {
			b.P("ON UPDATE", string(fk.OnUpdate))
		}
		if fk.OnDelete != "" {
			b.P("ON DELETE", string(fk.OnDelete))
		}
	})
}

func (s *state) copyRows(from *schema.Table, to *schema.Table, changes []schema.Change) error {
	var (
		args       []interface{}
		fromC, toC []string
	)
	for _, column := range to.Columns {
		// Find a change that associated with this column, if exists.
		var change schema.Change
		for i := range changes {
			switch c := changes[i].(type) {
			case *schema.AddColumn:
				if c.C.Name != column.Name {
					break
				}
				if change != nil {
					return fmt.Errorf("duplicate changes for column: %q: %T, %T", column.Name, change, c)
				}
				change = changes[i]
			case *schema.ModifyColumn:
				if c.To.Name != column.Name {
					break
				}
				if change != nil {
					return fmt.Errorf("duplicate changes for column: %q: %T, %T", column.Name, change, c)
				}
				change = changes[i]
			case *schema.DropColumn:
				if c.C.Name == column.Name {
					return fmt.Errorf("unexpected drop column: %q", column.Name)
				}
			}
		}
		switch change := change.(type) {
		// We expect that new columns are added with DEFAULT values,
		// or defined as nullable if the table is not empty.
		case *schema.AddColumn:
		// Column modification requires special handling if it was
		// converted from nullable to non-nullable with default value.
		case *schema.ModifyColumn:
			toC = append(toC, column.Name)
			if !column.Type.Null && column.Default != nil && change.Change.Is(schema.ChangeNull|schema.ChangeDefault) {
				fromC = append(fromC, fmt.Sprintf("IFNULL(`%[1]s`, ?) AS `%[1]s`", column.Name))
				x, err := defaultValue(column)
				if err != nil {
					return err
				}
				args = append(args, x)
			} else {
				fromC = append(fromC, column.Name)
			}
		// Columns without changes, should transfer as-is.
		case nil:
			toC = append(toC, column.Name)
			fromC = append(fromC, column.Name)
		}
	}
	stmt := fmt.Sprintf("INSERT INTO `%s` (%s) SELECT %s FROM `%s`", to.Name, identComma(toC), identComma(fromC), from.Name)
	s.append(&migrate.Change{
		Cmd:     stmt,
		Args:    args,
		Comment: fmt.Sprintf("copy rows from old table %q to new temporary table %q", from.Name, to.Name),
	})
	return nil
}

// alterTable alters the table with the given changes. Assuming the changes are "alterable".
func (s *state) alterTable(modify *schema.ModifyTable) error {
	for _, change := range modify.Changes {
		switch change := change.(type) {
		case *schema.AddIndex:
			if err := s.addIndexes(modify.T, change.I); err != nil {
				return err
			}
		case *schema.DropIndex:
			b := Build("DROP INDEX").Ident(change.I.Name)
			s.append(&migrate.Change{
				Cmd:     b.String(),
				Source:  change,
				Comment: fmt.Sprintf("drop index %q to table: %q", change.I.Name, modify.T.Name),
			})
		case *schema.AddColumn:
			b := Build("ALTER TABLE").Ident(modify.T.Name).P("ADD COLUMN")
			if err := s.column(b, change.C); err != nil {
				return err
			}
			// Unsupported reverse operation (DROP COLUMN).
			s.append(&migrate.Change{
				Cmd:     b.String(),
				Source:  change,
				Comment: fmt.Sprintf("add column %q to table: %q", change.C.Name, modify.T.Name),
			})
		default:
			return fmt.Errorf("unexpected change in alter table: %T", change)
		}
	}
	return nil
}

// tableSeq sets the sequence value of the table if it was provided by
// the user on table creation.
func (s *state) tableSeq(ctx context.Context, add *schema.AddTable) error {
	var inc AutoIncrement
	switch pk := add.T.PrimaryKey; {
	// Sequence was set on the table.
	case sqlx.Has(add.T.Attrs, &inc) && inc.Seq > 0:
	// Sequence was set on table primary-key (a single column PK).
	case pk != nil && len(pk.Parts) == 1 && pk.Parts[0].C != nil && sqlx.Has(pk.Parts[0].C.Attrs, &inc) && inc.Seq > 0:
	default:
		return nil
	}
	// SQLite tracks the AUTOINCREMENT in the "sqlite_sequence" table that is created and initialized automatically
	// whenever the first "PRIMARY KEY AUTOINCREMENT" is created. However, rows in this table are populated after the
	// first insertion to the associated table (name, seq). Therefore, we check if the sequence table and the row exist,
	// and in case they are not, we insert a new non zero sequence to it.
	rows, err := s.QueryContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name = ?", add.T.Name)
	if err != nil || !rows.Next() {
		s.append(&migrate.Change{
			Cmd:     fmt.Sprintf("INSERT INTO sqlite_sequence (name, seq) VALUES (%q, %d)", add.T.Name, inc.Seq),
			Source:  add,
			Reverse: fmt.Sprintf("UPDATE sqlite_sequence SET seq = 0 WHERE name = %q", add.T.Name),
			Comment: fmt.Sprintf("set sequence for %q table", add.T.Name),
		})
	}
	if rows != nil {
		err = rows.Close()
	}
	return err
}

func (s *state) append(c *migrate.Change) {
	s.Changes = append(s.Changes, c)
}

func alterable(modify *schema.ModifyTable) bool {
	for _, change := range modify.Changes {
		switch change := change.(type) {
		case *schema.DropIndex, *schema.AddIndex:
		case *schema.AddColumn:
			if len(change.C.Indexes) > 0 || len(change.C.ForeignKeys) > 0 || change.C.Default != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// checks writes the CHECK constraint to the builder.
func check(b *sqlx.Builder, c *schema.Check) {
	expr := c.Expr
	// Expressions should be wrapped with parens.
	if t := strings.TrimSpace(expr); !strings.HasPrefix(t, "(") || !strings.HasSuffix(t, ")") {
		expr = "(" + t + ")"
	}
	if c.Name != "" {
		b.P("CONSTRAINT").Ident(c.Name)
	}
	b.P("CHECK", expr)
}

func autoincPK(pk *schema.Index) bool {
	return sqlx.Has(pk.Attrs, &AutoIncrement{}) ||
		len(pk.Parts) == 1 && pk.Parts[0].C != nil && sqlx.Has(pk.Parts[0].C.Attrs, &AutoIncrement{})
}

// Build instantiates a new builder and writes the given phrase to it.
func Build(phrase string) *sqlx.Builder {
	b := &sqlx.Builder{QuoteChar: '`'}
	return b.P(phrase)
}

func defaultValue(c *schema.Column) (string, error) {
	switch x := c.Default.(type) {
	case *schema.Literal:
		return sqlx.SingleQuote(x.V)
	case *schema.RawExpr:
		return x.X, nil
	default:
		return "", fmt.Errorf("unexpected default value type: %T", x)
	}
}

func identComma(c []string) string {
	b := &sqlx.Builder{QuoteChar: '`'}
	b.MapComma(c, func(i int, b *sqlx.Builder) {
		if strings.ContainsRune(c[i], '`') {
			b.WriteString(c[i])
		} else {
			b.Ident(c[i])
		}
	})
	return b.String()
}
