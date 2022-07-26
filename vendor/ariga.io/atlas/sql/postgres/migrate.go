// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package postgres

import (
	"context"
	"fmt"
	"strconv"
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
// if the driver is unable to produce a plan to do so, or one of the statements
// is failed or unsupported.
func (p *planApply) ApplyChanges(ctx context.Context, changes []schema.Change) error {
	return sqlx.ApplyChanges(ctx, changes, p)
}

// state represents the state of a planning. It is not part of
// planApply so that multiple planning/applying can be called
// in parallel.
type state struct {
	conn
	migrate.Plan
}

// Exec executes the changes on the database. An error is returned
// if one of the operations fail, or a change is not supported.
func (s *state) plan(ctx context.Context, changes []schema.Change) error {
	planned := s.topLevel(changes)
	planned, err := sqlx.DetachCycles(planned)
	if err != nil {
		return err
	}
	for _, c := range planned {
		switch c := c.(type) {
		case *schema.AddTable:
			err = s.addTable(ctx, c)
		case *schema.DropTable:
			s.dropTable(c)
		case *schema.ModifyTable:
			err = s.modifyTable(ctx, c)
		default:
			err = fmt.Errorf("unsupported change %T", c)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// topLevel executes first the changes for creating or dropping schemas (top-level schema elements).
func (s *state) topLevel(changes []schema.Change) []schema.Change {
	planned := make([]schema.Change, 0, len(changes))
	for _, c := range changes {
		switch c := c.(type) {
		case *schema.AddSchema:
			b := Build("CREATE SCHEMA")
			if sqlx.Has(c.Extra, &schema.IfNotExists{}) {
				b.P("IF NOT EXISTS")
			}
			b.Ident(c.S.Name)
			s.append(&migrate.Change{
				Cmd:     b.String(),
				Source:  c,
				Reverse: Build("DROP SCHEMA").Ident(c.S.Name).String(),
				Comment: fmt.Sprintf("Add new schema named %q", c.S.Name),
			})
		case *schema.DropSchema:
			b := Build("DROP SCHEMA")
			if sqlx.Has(c.Extra, &schema.IfExists{}) {
				b.P("IF EXISTS")
			}
			b.Ident(c.S.Name)
			if sqlx.Has(c.Extra, &Cascade{}) {
				b.P("CASCADE")
			}
			s.append(&migrate.Change{
				Cmd:     b.String(),
				Source:  c,
				Comment: fmt.Sprintf("Drop schema named %q", c.S.Name),
			})
		default:
			planned = append(planned, c)
		}
	}
	return planned
}

// addTable builds and executes the query for creating a table in a schema.
func (s *state) addTable(ctx context.Context, add *schema.AddTable) error {
	// Create enum types before using them in the `CREATE TABLE` statement.
	if err := s.addTypes(ctx, add.T.Columns...); err != nil {
		return err
	}
	b := Build("CREATE TABLE")
	if sqlx.Has(add.Extra, &schema.IfNotExists{}) {
		b.P("IF NOT EXISTS")
	}
	b.Table(add.T)
	b.Wrap(func(b *sqlx.Builder) {
		b.MapComma(add.T.Columns, func(i int, b *sqlx.Builder) {
			s.column(b, add.T.Columns[i])
		})
		if pk := add.T.PrimaryKey; pk != nil {
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
	s.append(&migrate.Change{
		Cmd:     b.String(),
		Source:  add,
		Comment: fmt.Sprintf("create %q table", add.T.Name),
		Reverse: Build("DROP TABLE").Table(add.T).String(),
	})
	s.addIndexes(add.T, add.T.Indexes...)
	s.addComments(add.T)
	return nil
}

// dropTable builds and executes the query for dropping a table from a schema.
func (s *state) dropTable(drop *schema.DropTable) {
	b := Build("DROP TABLE")
	if sqlx.Has(drop.Extra, &schema.IfExists{}) {
		b.P("IF EXISTS")
	}
	b.Table(drop.T)
	s.append(&migrate.Change{
		Cmd:     b.String(),
		Source:  drop,
		Comment: fmt.Sprintf("drop %q table", drop.T.Name),
	})
}

// modifyTable builds the statements that bring the table into its modified state.
func (s *state) modifyTable(ctx context.Context, modify *schema.ModifyTable) error {
	var (
		changes     []schema.Change
		addI, dropI []*schema.Index
		comments    []*migrate.Change
	)
	for _, change := range skipAutoChanges(modify.Changes) {
		switch change := change.(type) {
		case *schema.AddAttr, *schema.ModifyAttr:
			from, to, err := commentChange(change)
			if err != nil {
				return err
			}
			comments = append(comments, s.tableComment(modify.T, to, from))
		case *schema.DropAttr:
			return fmt.Errorf("unsupported change type: %T", change)
		case *schema.AddIndex:
			if c := (schema.Comment{}); sqlx.Has(change.I.Attrs, &c) {
				comments = append(comments, s.indexComment(modify.T, change.I, c.Text, ""))
			}
			addI = append(addI, change.I)
		case *schema.DropIndex:
			dropI = append(dropI, change.I)
		case *schema.ModifyIndex:
			k := change.Change
			if change.Change.Is(schema.ChangeComment) {
				from, to, err := commentChange(sqlx.CommentDiff(change.From.Attrs, change.To.Attrs))
				if err != nil {
					return err
				}
				comments = append(comments, s.indexComment(modify.T, change.To, to, from))
				// If only the comment of the index was changed.
				if k &= ^schema.ChangeComment; k.Is(schema.NoChange) {
					continue
				}
			}
			// Index modification requires rebuilding the index.
			addI = append(addI, change.To)
			dropI = append(dropI, change.From)
		case *schema.ModifyForeignKey:
			// Foreign-key modification is translated into 2 steps.
			// Dropping the current foreign key and creating a new one.
			changes = append(changes, &schema.DropForeignKey{
				F: change.From,
			}, &schema.AddForeignKey{
				F: change.To,
			})
		case *schema.AddColumn:
			if err := s.addTypes(ctx, change.C); err != nil {
				return err
			}
			if c := (schema.Comment{}); sqlx.Has(change.C.Attrs, &c) {
				comments = append(comments, s.columnComment(modify.T, change.C, c.Text, ""))
			}
			changes = append(changes, change)
		case *schema.ModifyColumn:
			k := change.Change
			if change.Change.Is(schema.ChangeComment) {
				from, to, err := commentChange(sqlx.CommentDiff(change.From.Attrs, change.To.Attrs))
				if err != nil {
					return err
				}
				comments = append(comments, s.columnComment(modify.T, change.To, to, from))
				// If only the comment of the column was changed.
				if k &= ^schema.ChangeComment; k.Is(schema.NoChange) {
					continue
				}
			}
			from, ok1 := change.From.Type.Type.(*schema.EnumType)
			to, ok2 := change.To.Type.Type.(*schema.EnumType)
			switch {
			// Enum was changed.
			case ok1 && ok2 && from.T == to.T:
				if err := s.alterType(from, to); err != nil {
					return err
				}
				// If only the enum values were changed,
				// there is no need to ALTER the table.
				if k == schema.ChangeType {
					continue
				}
			// Enum was added (and column type was changed).
			case !ok1 && ok2:
				if err := s.addTypes(ctx, change.To); err != nil {
					return err
				}
			}
			changes = append(changes, change)
		default:
			changes = append(changes, change)
		}
	}
	s.dropIndexes(modify.T, dropI...)
	if len(changes) > 0 {
		if err := s.alterTable(modify.T, changes); err != nil {
			return err
		}
	}
	s.addIndexes(modify.T, addI...)
	s.append(comments...)
	return nil
}

// alterTable modifies the given table by executing on it a list of changes in one SQL statement.
func (s *state) alterTable(t *schema.Table, changes []schema.Change) error {
	var (
		errors     []string
		b          = Build("ALTER TABLE").Table(t)
		reverse    = Build("")
		reversible = true
	)
	b.MapComma(changes, func(i int, b *sqlx.Builder) {
		switch change := changes[i].(type) {
		case *schema.AddColumn:
			b.P("ADD COLUMN")
			s.column(b, change.C)
			reverse.Comma().P("DROP COLUMN").Ident(change.C.Name)
		case *schema.DropColumn:
			b.P("DROP COLUMN").Ident(change.C.Name)
			reversible = false
		case *schema.ModifyColumn:
			if err := s.alterColumn(b, change.Change, change.To); err != nil {
				errors = append(errors, err.Error())
			}
			if err := s.alterColumn(reverse, change.Change, change.From); err != nil {
				errors = append(errors, err.Error())
			}
		case *schema.AddForeignKey:
			b.P("ADD")
			s.fks(b, change.F)
			reverse.Comma().P("DROP CONSTRAINT").Ident(change.F.Symbol)
		case *schema.DropForeignKey:
			b.P("DROP CONSTRAINT").Ident(change.F.Symbol)
			reverse.P("ADD")
			s.fks(reverse, change.F)
		case *schema.AddCheck:
			check(b.P("ADD"), change.C)
			// Reverse operation is supported if
			// the constraint name is not generated.
			if reversible = change.C.Name != ""; reversible {
				reverse.Comma().P("DROP CONSTRAINT").Ident(change.C.Name)
			}
		case *schema.DropCheck:
			b.P("DROP CONSTRAINT").Ident(change.C.Name)
			check(reverse.Comma().P("ADD"), change.C)
		case *schema.ModifyCheck:
			switch {
			case change.From.Name == "":
				errors = append(errors, "cannot modify unnamed check constraint")
			case change.From.Name != change.To.Name:
				errors = append(errors, fmt.Sprintf("mismatch check constraint names: %q != %q", change.From.Name, change.To.Name))
			case change.From.Expr != change.To.Expr,
				sqlx.Has(change.From.Attrs, &NoInherit{}) && !sqlx.Has(change.To.Attrs, &NoInherit{}),
				!sqlx.Has(change.From.Attrs, &NoInherit{}) && sqlx.Has(change.To.Attrs, &NoInherit{}):
				b.P("DROP CONSTRAINT").Ident(change.From.Name).Comma().P("ADD")
				check(b, change.To)
				reverse.Comma().P("DROP CONSTRAINT").Ident(change.To.Name).Comma().P("ADD")
				check(reverse, change.From)
			default:
				errors = append(errors, "unknown check constraints change")
			}
		}
	})
	if len(errors) > 0 {
		return fmt.Errorf("alter table: %s", strings.Join(errors, ", "))
	}
	change := &migrate.Change{
		Cmd: b.String(),
		Source: &schema.ModifyTable{
			T:       t,
			Changes: changes,
		},
		Comment: fmt.Sprintf("Modify %q table", t.Name),
	}
	if reversible {
		b := Build("ALTER TABLE").Table(t)
		if _, err := b.ReadFrom(reverse); err != nil {
			return fmt.Errorf("unexpected buffer read: %w", err)
		}
		change.Reverse = b.String()
	}
	s.append(change)
	return nil
}

func (s *state) addComments(t *schema.Table) {
	var c schema.Comment
	if sqlx.Has(t.Attrs, &c) && c.Text != "" {
		s.append(s.tableComment(t, c.Text, ""))
	}
	for i := range t.Columns {
		if sqlx.Has(t.Columns[i].Attrs, &c) && c.Text != "" {
			s.append(s.columnComment(t, t.Columns[i], c.Text, ""))
		}
	}
	for i := range t.Indexes {
		if sqlx.Has(t.Indexes[i].Attrs, &c) && c.Text != "" {
			s.append(s.indexComment(t, t.Indexes[i], c.Text, ""))
		}
	}
}

func (*state) tableComment(t *schema.Table, to, from string) *migrate.Change {
	b := Build("COMMENT ON TABLE").Table(t).P("IS")
	return &migrate.Change{
		Cmd:     b.Clone().P(quote(to)).String(),
		Comment: fmt.Sprintf("set comment to table: %q", t.Name),
		Reverse: b.Clone().P(quote(from)).String(),
	}
}

func (*state) columnComment(t *schema.Table, c *schema.Column, to, from string) *migrate.Change {
	b := Build("COMMENT ON COLUMN").Table(t)
	b.WriteByte('.')
	b.Ident(c.Name).P("IS")
	return &migrate.Change{
		Cmd:     b.Clone().P(quote(to)).String(),
		Comment: fmt.Sprintf("set comment to column: %q on table: %q", c.Name, t.Name),
		Reverse: b.Clone().P(quote(from)).String(),
	}
}

func (*state) indexComment(t *schema.Table, idx *schema.Index, to, from string) *migrate.Change {
	b := Build("COMMENT ON INDEX").Ident(idx.Name).P("IS")
	return &migrate.Change{
		Cmd:     b.Clone().P(quote(to)).String(),
		Comment: fmt.Sprintf("set comment to index: %q on table: %q", idx.Name, t.Name),
		Reverse: b.Clone().P(quote(from)).String(),
	}
}

func (s *state) dropIndexes(t *schema.Table, indexes ...*schema.Index) {
	rs := &state{conn: s.conn}
	rs.addIndexes(t, indexes...)
	for i, idx := range indexes {
		s.append(&migrate.Change{
			Cmd:     rs.Changes[i].Reverse,
			Comment: fmt.Sprintf("Drop index %q from table: %q", idx.Name, t.Name),
			Reverse: rs.Changes[i].Cmd,
		})
	}
}

func (s *state) addTypes(ctx context.Context, columns ...*schema.Column) error {
	for _, c := range columns {
		e, ok := c.Type.Type.(*schema.EnumType)
		if !ok {
			continue
		}
		if e.T == "" {
			return fmt.Errorf("missing enum name for column %q", c.Name)
		}
		c.Type.Raw = e.T
		if exists, err := s.enumExists(ctx, e.T); err != nil {
			return err
		} else if exists {
			continue
		}
		b := Build("CREATE TYPE").Ident(e.T).P("AS ENUM")
		b.Wrap(func(b *sqlx.Builder) {
			b.MapComma(e.Values, func(i int, b *sqlx.Builder) {
				b.WriteString("'" + e.Values[i] + "'")
			})
		})
		s.append(&migrate.Change{
			Cmd:     b.String(),
			Comment: fmt.Sprintf("create enum type %q", e.T),
			Reverse: Build("DROP TYPE").Ident(e.T).String(),
		})
	}
	return nil
}

func (s *state) alterType(from, to *schema.EnumType) error {
	if len(from.Values) > len(to.Values) {
		return fmt.Errorf("dropping enum (%q) value is not supported", from.T)
	}
	for i := range from.Values {
		if from.Values[i] != to.Values[i] {
			return fmt.Errorf("replacing or reordering enum (%q) value is not supported: %q != %q", to.T, to.Values, from.Values)
		}
	}
	for _, v := range to.Values[len(from.Values):] {
		s.append(&migrate.Change{
			Cmd:     Build("ALTER TYPE").Ident(from.T).P("ADD VALUE", quote(v)).String(),
			Comment: fmt.Sprintf("add value to enum type: %q", from.T),
		})
	}
	return nil
}

func (s *state) enumExists(ctx context.Context, name string) (bool, error) {
	rows, err := s.QueryContext(ctx, "SELECT * FROM pg_type WHERE typname = $1 AND typtype = 'e'", name)
	if err != nil {
		return false, fmt.Errorf("check index existence: %w", err)
	}
	defer rows.Close()
	return rows.Next(), rows.Err()
}

func (s *state) addIndexes(t *schema.Table, indexes ...*schema.Index) {
	for _, idx := range indexes {
		b := Build("CREATE")
		if idx.Unique {
			b.P("UNIQUE")
		}
		b.P("INDEX")
		if idx.Name != "" {
			b.Ident(idx.Name)
		}
		b.P("ON").Table(t)
		s.index(b, idx)
		s.append(&migrate.Change{
			Cmd:     b.String(),
			Comment: fmt.Sprintf("Create index %q to table: %q", idx.Name, t.Name),
			Reverse: func() string {
				b := Build("DROP INDEX")
				// Unlike MySQL, the DROP command is not attached to ALTER TABLE.
				// Therefore, we print indexes with their qualified name, because
				// the connection that executes the statements may not be attached
				// to the this schema.
				if t.Schema != nil {
					b.WriteByte(b.QuoteChar)
					b.WriteString(t.Schema.Name)
					b.WriteByte(b.QuoteChar)
					b.WriteByte('.')
				}
				b.Ident(idx.Name)
				return b.String()
			}(),
		})
	}
}

func (s *state) column(b *sqlx.Builder, c *schema.Column) {
	b.Ident(c.Name).P(mustFormat(c.Type.Type))
	if !c.Type.Null {
		b.P("NOT")
	}
	b.P("NULL")
	s.columnDefault(b, c)
	for _, attr := range c.Attrs {
		switch a := attr.(type) {
		case *schema.Comment:
		case *schema.Collation:
			b.P("COLLATE").Ident(a.V)
		case *Identity:
			// Handled below.
		default:
			panic(fmt.Sprintf("unexpected column attribute: %T", attr))
		}
	}
	id, ok := identity(c.Attrs)
	if !ok {
		return
	}
	b.P("GENERATED", id.Generation, "AS IDENTITY")
	if id.Sequence.Start != defaultSeqStart || id.Sequence.Increment != defaultSeqIncrement {
		b.Wrap(func(b *sqlx.Builder) {
			if id.Sequence.Start != defaultSeqStart {
				b.P("START WITH", strconv.FormatInt(id.Sequence.Start, 10))
			}
			if id.Sequence.Increment != defaultSeqIncrement {
				b.P("INCREMENT BY", strconv.FormatInt(id.Sequence.Increment, 10))
			}
		})
	}
}

// columnDefault writes the default value of column to the builder.
func (s *state) columnDefault(b *sqlx.Builder, c *schema.Column) {
	switch x := c.Default.(type) {
	case *schema.Literal:
		v := x.V
		switch c.Type.Type.(type) {
		case *schema.BoolType, *schema.DecimalType, *schema.IntegerType, *schema.FloatType:
		default:
			v = quote(v)
		}
		b.P("DEFAULT", v)
	case *schema.RawExpr:
		// Ignore identity functions added by the differ.
		if _, ok := c.Type.Type.(*SerialType); !ok {
			b.P("DEFAULT", x.X)
		}
	}
}

func (s *state) alterColumn(b *sqlx.Builder, k schema.ChangeKind, c *schema.Column) error {
	for !k.Is(schema.NoChange) {
		b.P("ALTER COLUMN").Ident(c.Name)
		switch {
		case k.Is(schema.ChangeType):
			b.P("TYPE").P(mustFormat(c.Type.Type))
			if collate := (schema.Collation{}); sqlx.Has(c.Attrs, &collate) {
				b.P("COLLATE", collate.V)
			}
			k &= ^schema.ChangeType
		case k.Is(schema.ChangeNull) && c.Type.Null:
			b.P("DROP NOT NULL")
			k &= ^schema.ChangeNull
		case k.Is(schema.ChangeNull) && !c.Type.Null:
			b.P("SET NOT NULL")
			k &= ^schema.ChangeNull
		case k.Is(schema.ChangeDefault) && c.Default == nil:
			b.P("DROP DEFAULT")
			k &= ^schema.ChangeDefault
		case k.Is(schema.ChangeDefault) && c.Default != nil:
			s.columnDefault(b.P("SET"), c)
			k &= ^schema.ChangeDefault
		case k.Is(schema.ChangeAttr):
			id, ok := identity(c.Attrs)
			if !ok {
				return fmt.Errorf("unexpected attribute change (expect IDENTITY): %v", c.Attrs)
			}
			// The syntax for altering identity columns is identical to sequence_options.
			// https://www.postgresql.org/docs/current/sql-altersequence.html
			b.P("SET GENERATED", id.Generation, "SET START WITH", strconv.FormatInt(id.Sequence.Start, 10), "SET INCREMENT BY", strconv.FormatInt(id.Sequence.Increment, 10), "RESTART")
			k &= ^schema.ChangeAttr
		case k.Is(schema.ChangeComment):
			// Handled separately on modifyTable.
			k &= ^schema.ChangeComment
		default:
			return fmt.Errorf("unexpected column change: %d", k)
		}
		if !k.Is(schema.NoChange) {
			b.Comma()
		}
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
			s.partAttrs(b, parts[i])
		})
	})
}

func (s *state) partAttrs(b *sqlx.Builder, p *schema.IndexPart) {
	if p.Desc {
		b.P("DESC")
	}
	for _, attr := range p.Attrs {
		switch attr := attr.(type) {
		case *IndexColumnProperty:
			switch {
			// Defaults when DESC is specified.
			case p.Desc && attr.NullsFirst:
			case p.Desc && attr.NullsLast:
				b.P("NULL LAST")
			// Defaults when DESC is not specified.
			case !p.Desc && attr.NullsLast:
			case !p.Desc && attr.NullsFirst:
				b.P("NULL FIRST")
			}
		case *schema.Collation:
			b.P("COLLATE").Ident(attr.V)
		default:
			panic(fmt.Sprintf("unexpected index part attribute: %T", attr))
		}
	}
}

func (s *state) index(b *sqlx.Builder, idx *schema.Index) {
	// Avoid appending the default method.
	if t := (IndexType{}); sqlx.Has(idx.Attrs, &t) && strings.ToUpper(t.T) != IndexTypeBTree {
		b.P("USING", t.T)
	}
	s.indexParts(b, idx.Parts)
	if p := (IndexPredicate{}); sqlx.Has(idx.Attrs, &p) {
		b.P("WHERE").P(p.P)
	}
	for _, attr := range idx.Attrs {
		switch attr.(type) {
		case *schema.Comment, *ConType, *IndexType, *IndexPredicate:
		default:
			panic(fmt.Sprintf("unexpected index attribute: %T", attr))
		}
	}
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
		b.P("REFERENCES").Table(fk.RefTable)
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

func (s *state) append(c ...*migrate.Change) {
	s.Changes = append(s.Changes, c...)
}

// Build instantiates a new builder and writes the given phrase to it.
func Build(phrase string) *sqlx.Builder {
	b := &sqlx.Builder{QuoteChar: '"'}
	return b.P(phrase)
}

// skipAutoChanges filters unnecessary changes that are automatically
// happened by the database when ALTER TABLE is executed.
func skipAutoChanges(changes []schema.Change) []schema.Change {
	var (
		dropC   = make(map[string]bool)
		planned = make([]schema.Change, 0, len(changes))
	)
	for _, c := range changes {
		if c, ok := c.(*schema.DropColumn); ok {
			dropC[c.C.Name] = true
		}
	}
search:
	for _, c := range changes {
		switch c := c.(type) {
		// Indexes involving the column are automatically dropped
		// with it. This true for multi-columns indexes as well.
		// See https://www.postgresql.org/docs/current/sql-altertable.html
		case *schema.DropIndex:
			for _, p := range c.I.Parts {
				if p.C != nil && dropC[p.C.Name] {
					continue search
				}
			}
		// Simple case for skipping constraint dropping,
		// if the child table columns were dropped.
		case *schema.DropForeignKey:
			for _, c := range c.F.Columns {
				if dropC[c.Name] {
					continue search
				}
			}
		}
		planned = append(planned, c)
	}
	return planned
}

// commentChange extracts the information for modifying a comment from the given change.
func commentChange(c schema.Change) (from, to string, err error) {
	switch c := c.(type) {
	case *schema.AddAttr:
		toC, ok := c.A.(*schema.Comment)
		if ok {
			to = toC.Text
			return
		}
		err = fmt.Errorf("unexpected AddAttr.(%T) for comment change", c.A)
	case *schema.ModifyAttr:
		fromC, ok1 := c.From.(*schema.Comment)
		toC, ok2 := c.To.(*schema.Comment)
		if ok1 && ok2 {
			from, to = fromC.Text, toC.Text
			return
		}
		err = fmt.Errorf("unsupported ModifyAttr(%T, %T) change", c.From, c.To)
	default:
		err = fmt.Errorf("unexpected change %T", c)
	}
	return
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
	if sqlx.Has(c.Attrs, &NoInherit{}) {
		b.P("NO INHERIT")
	}
}

func quote(s string) string {
	if sqlx.IsQuoted(s, '\'') {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
