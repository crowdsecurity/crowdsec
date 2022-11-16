// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package postgres

import (
	"context"
	"errors"
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
func (p *planApply) PlanChanges(ctx context.Context, name string, changes []schema.Change, opts ...migrate.PlanOption) (*migrate.Plan, error) {
	s := &state{
		conn: p.conn,
		Plan: migrate.Plan{
			Name:          name,
			Reversible:    true,
			Transactional: true,
		},
		created: make(map[string]*schema.EnumType),
		altered: make(map[string]*schema.EnumType),
		dropped: make(map[string]*schema.EnumType),
	}
	for _, o := range opts {
		o(&s.PlanOptions)
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
func (p *planApply) ApplyChanges(ctx context.Context, changes []schema.Change, opts ...migrate.PlanOption) error {
	return sqlx.ApplyChanges(ctx, changes, p, opts...)
}

// state represents the state of a planning. It is not part of
// planApply so that multiple planning/applying can be called
// in parallel.
type state struct {
	conn
	migrate.Plan
	migrate.PlanOptions
	// Track the enums that were created, altered and
	// dropped, in this phase to avoid duplicate updates.
	created, altered, dropped map[string]*schema.EnumType
}

// Exec executes the changes on the database. An error is returned
// if one of the operations fail, or a change is not supported.
func (s *state) plan(ctx context.Context, changes []schema.Change) error {
	if s.SchemaQualifier != nil {
		if err := sqlx.CheckChangesScope(changes); err != nil {
			return err
		}
	}
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
		case *schema.RenameTable:
			s.renameTable(c)
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
			b := s.Build("CREATE SCHEMA")
			if sqlx.Has(c.Extra, &schema.IfNotExists{}) {
				b.P("IF NOT EXISTS")
			}
			b.Ident(c.S.Name)
			s.append(&migrate.Change{
				Cmd:     b.String(),
				Source:  c,
				Reverse: s.Build("DROP SCHEMA").Ident(c.S.Name).P("CASCADE").String(),
				Comment: fmt.Sprintf("Add new schema named %q", c.S.Name),
			})
		case *schema.DropSchema:
			b := s.Build("DROP SCHEMA")
			if sqlx.Has(c.Extra, &schema.IfExists{}) {
				b.P("IF EXISTS")
			}
			b.Ident(c.S.Name).P("CASCADE")
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
	if err := s.mayAddEnums(ctx, add.T, add.T.Columns...); err != nil {
		return err
	}
	var (
		errs []string
		b    = s.Build("CREATE TABLE")
	)
	if sqlx.Has(add.Extra, &schema.IfNotExists{}) {
		b.P("IF NOT EXISTS")
	}
	b.Table(add.T)
	b.Wrap(func(b *sqlx.Builder) {
		b.MapComma(add.T.Columns, func(i int, b *sqlx.Builder) {
			if err := s.column(b, add.T, add.T.Columns[i]); err != nil {
				errs = append(errs, err.Error())
			}
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
	if p := (Partition{}); sqlx.Has(add.T.Attrs, &p) {
		s, err := formatPartition(p)
		if err != nil {
			errs = append(errs, err.Error())
		}
		b.P(s)
	}
	if len(errs) > 0 {
		return fmt.Errorf("create table %q: %s", add.T.Name, strings.Join(errs, ", "))
	}
	s.append(&migrate.Change{
		Cmd:     b.String(),
		Source:  add,
		Comment: fmt.Sprintf("create %q table", add.T.Name),
		Reverse: s.Build("DROP TABLE").Table(add.T).String(),
	})
	s.addIndexes(add.T, add.T.Indexes...)
	s.addComments(add.T)
	return nil
}

// dropTable builds and executes the query for dropping a table from a schema.
func (s *state) dropTable(drop *schema.DropTable) {
	b := s.Build("DROP TABLE")
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
		alter       []schema.Change
		addI, dropI []*schema.Index
		changes     []*migrate.Change
	)
	for _, change := range skipAutoChanges(modify.Changes) {
		switch change := change.(type) {
		case *schema.AddAttr, *schema.ModifyAttr:
			from, to, err := commentChange(change)
			if err != nil {
				return err
			}
			changes = append(changes, s.tableComment(modify.T, to, from))
		case *schema.DropAttr:
			return fmt.Errorf("unsupported change type: %T", change)
		case *schema.AddIndex:
			if c := (schema.Comment{}); sqlx.Has(change.I.Attrs, &c) {
				changes = append(changes, s.indexComment(modify.T, change.I, c.Text, ""))
			}
			addI = append(addI, change.I)
		case *schema.DropIndex:
			// Unlike DROP INDEX statements that are executed separately,
			// DROP CONSTRAINT are added to the ALTER TABLE statement below.
			if isUniqueConstraint(change.I) {
				alter = append(alter, change)
			} else {
				dropI = append(dropI, change.I)
			}
		case *schema.ModifyIndex:
			k := change.Change
			if change.Change.Is(schema.ChangeComment) {
				from, to, err := commentChange(sqlx.CommentDiff(change.From.Attrs, change.To.Attrs))
				if err != nil {
					return err
				}
				changes = append(changes, s.indexComment(modify.T, change.To, to, from))
				// If only the comment of the index was changed.
				if k &= ^schema.ChangeComment; k.Is(schema.NoChange) {
					continue
				}
			}
			// Index modification requires rebuilding the index.
			addI = append(addI, change.To)
			dropI = append(dropI, change.From)
		case *schema.RenameIndex:
			changes = append(changes, &migrate.Change{
				Source:  change,
				Comment: fmt.Sprintf("rename an index from %q to %q", change.From.Name, change.To.Name),
				Cmd:     s.Build("ALTER INDEX").Ident(change.From.Name).P("RENAME TO").Ident(change.To.Name).String(),
				Reverse: s.Build("ALTER INDEX").Ident(change.To.Name).P("RENAME TO").Ident(change.From.Name).String(),
			})
		case *schema.ModifyForeignKey:
			// Foreign-key modification is translated into 2 steps.
			// Dropping the current foreign key and creating a new one.
			alter = append(alter, &schema.DropForeignKey{
				F: change.From,
			}, &schema.AddForeignKey{
				F: change.To,
			})
		case *schema.AddColumn:
			if err := s.mayAddEnums(ctx, modify.T, change.C); err != nil {
				return err
			}
			if c := (schema.Comment{}); sqlx.Has(change.C.Attrs, &c) {
				changes = append(changes, s.columnComment(modify.T, change.C, c.Text, ""))
			}
			alter = append(alter, change)
		case *schema.ModifyColumn:
			k := change.Change
			if change.Change.Is(schema.ChangeComment) {
				from, to, err := commentChange(sqlx.CommentDiff(change.From.Attrs, change.To.Attrs))
				if err != nil {
					return err
				}
				changes = append(changes, s.columnComment(modify.T, change.To, to, from))
				// If only the comment of the column was changed.
				if k &= ^schema.ChangeComment; k.Is(schema.NoChange) {
					continue
				}
			}
			from, ok1 := hasEnumType(change.From)
			to, ok2 := hasEnumType(change.To)
			switch {
			// Enum was changed (underlying values).
			case ok1 && ok2 && s.enumIdent(modify.T.Schema, from) == s.enumIdent(modify.T.Schema, to):
				if err := s.alterEnum(modify.T, from, to); err != nil {
					return err
				}
				// If only the enum values were changed,
				// there is no need to ALTER the table.
				if k == schema.ChangeType {
					continue
				}
			// Enum was added or changed.
			case !ok1 && ok2 ||
				ok1 && ok2 && s.enumIdent(modify.T.Schema, from) != s.enumIdent(modify.T.Schema, to):
				if err := s.mayAddEnums(ctx, modify.T, change.To); err != nil {
					return err
				}
			}
			alter = append(alter, &schema.ModifyColumn{To: change.To, From: change.From, Change: k})
		case *schema.RenameColumn:
			// "RENAME COLUMN" cannot be combined with other alterations.
			b := s.Build("ALTER TABLE").Table(modify.T).P("RENAME COLUMN")
			r := b.Clone()
			changes = append(changes, &migrate.Change{
				Source:  change,
				Comment: fmt.Sprintf("rename a column from %q to %q", change.From.Name, change.To.Name),
				Cmd:     b.Ident(change.From.Name).P("TO").Ident(change.To.Name).String(),
				Reverse: r.Ident(change.To.Name).P("TO").Ident(change.From.Name).String(),
			})
		default:
			alter = append(alter, change)
		}
	}
	s.dropIndexes(modify.T, dropI...)
	if len(alter) > 0 {
		if err := s.alterTable(modify.T, alter); err != nil {
			return err
		}
	}
	s.addIndexes(modify.T, addI...)
	s.append(changes...)
	return nil
}

// alterTable modifies the given table by executing on it a list of changes in one SQL statement.
func (s *state) alterTable(t *schema.Table, changes []schema.Change) error {
	var (
		reverse    []schema.Change
		reversible = true
	)
	build := func(alter *alterChange, changes []schema.Change) (string, error) {
		b := s.Build("ALTER TABLE").Table(t)
		err := b.MapCommaErr(changes, func(i int, b *sqlx.Builder) error {
			switch change := changes[i].(type) {
			case *schema.AddColumn:
				b.P("ADD COLUMN")
				if err := s.column(b, t, change.C); err != nil {
					return err
				}
				reverse = append(reverse, &schema.DropColumn{C: change.C})
			case *schema.ModifyColumn:
				if err := s.alterColumn(b, alter, t, change); err != nil {
					return err
				}
				if change.Change.Is(schema.ChangeGenerated) {
					reversible = false
				}
				reverse = append(reverse, &schema.ModifyColumn{
					From:   change.To,
					To:     change.From,
					Change: change.Change & ^schema.ChangeGenerated,
				})
				toE, toHas := hasEnumType(change.To)
				fromE, fromHas := hasEnumType(change.From)
				// In case the enum was dropped or replaced with a different one.
				if fromHas && !toHas || fromHas && toHas && s.enumIdent(t.Schema, fromE) != s.enumIdent(t.Schema, toE) {
					if err := s.mayDropEnum(alter, t.Schema, fromE); err != nil {
						return err
					}
				}
			case *schema.DropColumn:
				b.P("DROP COLUMN").Ident(change.C.Name)
				reverse = append(reverse, &schema.AddColumn{C: change.C})
				if e, ok := hasEnumType(change.C); ok {
					if err := s.mayDropEnum(alter, t.Schema, e); err != nil {
						return err
					}
				}
			case *schema.AddIndex:
				b.P("ADD CONSTRAINT").Ident(change.I.Name).P("UNIQUE")
				s.indexParts(b, change.I.Parts)
				// Skip reversing this operation as it is the inverse of
				// the operation below and should not be used besides this.
			case *schema.DropIndex:
				b.P("DROP CONSTRAINT").Ident(change.I.Name)
				reverse = append(reverse, &schema.AddIndex{I: change.I})
			case *schema.AddForeignKey:
				b.P("ADD")
				s.fks(b, change.F)
				reverse = append(reverse, &schema.DropForeignKey{F: change.F})
			case *schema.DropForeignKey:
				b.P("DROP CONSTRAINT").Ident(change.F.Symbol)
				reverse = append(reverse, &schema.AddForeignKey{F: change.F})
			case *schema.AddCheck:
				check(b.P("ADD"), change.C)
				// Reverse operation is supported if
				// the constraint name is not generated.
				if reversible = reversible && change.C.Name != ""; reversible {
					reverse = append(reverse, &schema.DropCheck{C: change.C})
				}
			case *schema.DropCheck:
				b.P("DROP CONSTRAINT").Ident(change.C.Name)
				reverse = append(reverse, &schema.AddCheck{C: change.C})
			case *schema.ModifyCheck:
				switch {
				case change.From.Name == "":
					return errors.New("cannot modify unnamed check constraint")
				case change.From.Name != change.To.Name:
					return fmt.Errorf("mismatch check constraint names: %q != %q", change.From.Name, change.To.Name)
				case change.From.Expr != change.To.Expr,
					sqlx.Has(change.From.Attrs, &NoInherit{}) && !sqlx.Has(change.To.Attrs, &NoInherit{}),
					!sqlx.Has(change.From.Attrs, &NoInherit{}) && sqlx.Has(change.To.Attrs, &NoInherit{}):
					b.P("DROP CONSTRAINT").Ident(change.From.Name).Comma().P("ADD")
					check(b, change.To)
				default:
					return errors.New("unknown check constraint change")
				}
				reverse = append(reverse, &schema.ModifyCheck{
					From: change.To,
					To:   change.From,
				})
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		return b.String(), nil
	}
	cmd := &alterChange{}
	stmt, err := build(cmd, changes)
	if err != nil {
		return fmt.Errorf("alter table %q: %v", t.Name, err)
	}
	cmd.main = &migrate.Change{
		Cmd: stmt,
		Source: &schema.ModifyTable{
			T:       t,
			Changes: changes,
		},
		Comment: fmt.Sprintf("modify %q table", t.Name),
	}
	if reversible {
		// Changes should be reverted in
		// a reversed order they were created.
		sqlx.ReverseChanges(reverse)
		if cmd.main.Reverse, err = build(&alterChange{}, reverse); err != nil {
			return fmt.Errorf("reverse alter table %q: %v", t.Name, err)
		}
	}
	cmd.append(s)
	return nil
}

// alterChange describes an alter table migrate.Change where its main command
// can be supported by additional statements before and after it is executed.
type alterChange struct {
	main          *migrate.Change
	before, after []*migrate.Change
}

func (a *alterChange) append(s *state) {
	s.append(a.before...)
	s.append(a.main)
	s.append(a.after...)
}

func (s *state) alterColumn(b *sqlx.Builder, alter *alterChange, t *schema.Table, c *schema.ModifyColumn) error {
	for k := c.Change; !k.Is(schema.NoChange); {
		b.P("ALTER COLUMN").Ident(c.To.Name)
		switch {
		case k.Is(schema.ChangeType):
			if err := s.alterType(b, alter, t, c); err != nil {
				return err
			}
			k &= ^schema.ChangeType
		case k.Is(schema.ChangeNull) && c.To.Type.Null:
			if t, ok := c.To.Type.Type.(*SerialType); ok {
				return fmt.Errorf("NOT NULL constraint is required for %s column %q", t.T, c.To.Name)
			}
			b.P("DROP NOT NULL")
			k &= ^schema.ChangeNull
		case k.Is(schema.ChangeNull) && !c.To.Type.Null:
			b.P("SET NOT NULL")
			k &= ^schema.ChangeNull
		case k.Is(schema.ChangeDefault) && c.To.Default == nil:
			b.P("DROP DEFAULT")
			k &= ^schema.ChangeDefault
		case k.Is(schema.ChangeDefault) && c.To.Default != nil:
			s.columnDefault(b.P("SET"), c.To)
			k &= ^schema.ChangeDefault
		case k.Is(schema.ChangeAttr):
			toI, ok := identity(c.To.Attrs)
			if !ok {
				return fmt.Errorf("unexpected attribute change (expect IDENTITY): %v", c.To.Attrs)
			}
			// The syntax for altering identity columns is identical to sequence_options.
			// https://www.postgresql.org/docs/current/sql-altersequence.html
			b.P("SET GENERATED", toI.Generation, "SET START WITH", strconv.FormatInt(toI.Sequence.Start, 10), "SET INCREMENT BY", strconv.FormatInt(toI.Sequence.Increment, 10))
			// Skip SEQUENCE RESTART in case the "start value" is less than the "current value" in one
			// of the states (inspected and desired), because this function is used for both UP and DOWN.
			if fromI, ok := identity(c.From.Attrs); (!ok || fromI.Sequence.Last < toI.Sequence.Start) && toI.Sequence.Last < toI.Sequence.Start {
				b.P("RESTART")
			}
			k &= ^schema.ChangeAttr
		case k.Is(schema.ChangeGenerated):
			if sqlx.Has(c.To.Attrs, &schema.GeneratedExpr{}) {
				return fmt.Errorf("unexpected generation expression change (expect DROP EXPRESSION): %v", c.To.Attrs)
			}
			b.P("DROP EXPRESSION")
			k &= ^schema.ChangeGenerated
		default: // e.g. schema.ChangeComment.
			return fmt.Errorf("unexpected column change: %d", k)
		}
		if !k.Is(schema.NoChange) {
			b.Comma()
		}
	}
	return nil
}

// alterType appends the clause(s) to alter the column type and assuming the
// "ALTER COLUMN <Name>" was called before by the alterColumn function.
func (s *state) alterType(b *sqlx.Builder, alter *alterChange, t *schema.Table, c *schema.ModifyColumn) error {
	// Commands for creating and dropping serial sequences.
	createDropSeq := func(st *SerialType) (string, string, string) {
		seq := fmt.Sprintf(`%s%q`, s.schemaPrefix(t.Schema), st.sequence(t, c.To))
		drop := s.Build("DROP SEQUENCE IF EXISTS").P(seq).String()
		create := s.Build("CREATE SEQUENCE IF NOT EXISTS").P(seq, "OWNED BY").
			P(fmt.Sprintf(`%s%q.%q`, s.schemaPrefix(t.Schema), t.Name, c.To.Name)).
			String()
		return create, drop, seq
	}
	toS, toHas := c.To.Type.Type.(*SerialType)
	fromS, fromHas := c.From.Type.Type.(*SerialType)
	switch {
	// Sequence was dropped.
	case fromHas && !toHas:
		b.P("DROP DEFAULT")
		create, drop, _ := createDropSeq(fromS)
		// Sequence should be deleted after it was dropped
		// from the DEFAULT value.
		alter.after = append(alter.after, &migrate.Change{
			Source:  c,
			Comment: fmt.Sprintf("drop sequence used by serial column %q", c.From.Name),
			Cmd:     drop,
			Reverse: create,
		})
		toT, err := FormatType(c.To.Type.Type)
		if err != nil {
			return err
		}
		fromT, err := FormatType(fromS.IntegerType())
		if err != nil {
			return err
		}
		// Underlying type was changed. e.g. serial to bigint.
		if toT != fromT {
			b.Comma().P("ALTER COLUMN").Ident(c.To.Name).P("TYPE", toT)
		}
	// Sequence was added.
	case !fromHas && toHas:
		create, drop, seq := createDropSeq(toS)
		// Sequence should be created before it is used by the
		// column DEFAULT value.
		alter.before = append(alter.before, &migrate.Change{
			Source:  c,
			Comment: fmt.Sprintf("create sequence for serial column %q", c.To.Name),
			Cmd:     create,
			Reverse: drop,
		})
		b.P("SET DEFAULT", fmt.Sprintf("nextval('%s')", seq))
		toT, err := FormatType(toS.IntegerType())
		if err != nil {
			return err
		}
		fromT, err := FormatType(c.From.Type.Type)
		if err != nil {
			return err
		}
		// Underlying type was changed. e.g. integer to bigserial (bigint).
		if toT != fromT {
			b.Comma().P("ALTER COLUMN").Ident(c.To.Name).P("TYPE", toT)
		}
	// Serial type was changed. e.g. serial to bigserial.
	case fromHas && toHas:
		f, err := FormatType(toS.IntegerType())
		if err != nil {
			return err
		}
		b.P("TYPE", f)
	default:
		var (
			f   string
			err error
		)
		if e, ok := c.To.Type.Type.(*schema.EnumType); ok {
			f = s.enumIdent(t.Schema, e)
		} else if f, err = FormatType(c.To.Type.Type); err != nil {
			return err
		}
		b.P("TYPE", f)
	}
	if collate := (schema.Collation{}); sqlx.Has(c.To.Attrs, &collate) {
		b.P("COLLATE", collate.V)
	}
	return nil
}

func (s *state) renameTable(c *schema.RenameTable) {
	s.append(&migrate.Change{
		Source:  c,
		Comment: fmt.Sprintf("rename a table from %q to %q", c.From.Name, c.To.Name),
		Cmd:     s.Build("ALTER TABLE").Table(c.From).P("RENAME TO").Table(c.To).String(),
		Reverse: s.Build("ALTER TABLE").Table(c.To).P("RENAME TO").Table(c.From).String(),
	})
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

func (s *state) tableComment(t *schema.Table, to, from string) *migrate.Change {
	b := s.Build("COMMENT ON TABLE").Table(t).P("IS")
	return &migrate.Change{
		Cmd:     b.Clone().P(quote(to)).String(),
		Comment: fmt.Sprintf("set comment to table: %q", t.Name),
		Reverse: b.Clone().P(quote(from)).String(),
	}
}

func (s *state) columnComment(t *schema.Table, c *schema.Column, to, from string) *migrate.Change {
	b := s.Build("COMMENT ON COLUMN").Table(t)
	b.WriteByte('.')
	b.Ident(c.Name).P("IS")
	return &migrate.Change{
		Cmd:     b.Clone().P(quote(to)).String(),
		Comment: fmt.Sprintf("set comment to column: %q on table: %q", c.Name, t.Name),
		Reverse: b.Clone().P(quote(from)).String(),
	}
}

func (s *state) indexComment(t *schema.Table, idx *schema.Index, to, from string) *migrate.Change {
	b := s.Build("COMMENT ON INDEX").Ident(idx.Name).P("IS")
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
			Comment: fmt.Sprintf("drop index %q from table: %q", idx.Name, t.Name),
			Reverse: rs.Changes[i].Cmd,
		})
	}
}

func (s *state) mayAddEnums(ctx context.Context, t *schema.Table, columns ...*schema.Column) error {
	for _, c := range columns {
		e, ok := hasEnumType(c)
		if !ok {
			continue
		}
		if e.T == "" {
			return fmt.Errorf("missing enum name for column %q", c.Name)
		}
		if exists, err := s.enumExists(ctx, t.Schema, e); err != nil {
			return err
		} else if exists {
			// Enum exists and was not created
			// on this migration phase.
			continue
		}
		name := s.enumIdent(t.Schema, e)
		if prev, ok := s.created[name]; ok {
			if !sqlx.ValuesEqual(prev.Values, e.Values) {
				return fmt.Errorf("enum type %s has inconsistent desired state: %q != %q", name, prev.Values, e.Values)
			}
			continue
		}
		s.created[name] = e
		create, drop := s.createDropEnum(t.Schema, e)
		s.append(&migrate.Change{
			Cmd:     create,
			Reverse: drop,
			Comment: fmt.Sprintf("create enum type %q", e.T),
		})
	}
	return nil
}

func (s *state) alterEnum(t *schema.Table, from, to *schema.EnumType) error {
	if len(from.Values) > len(to.Values) {
		return fmt.Errorf("dropping enum (%q) value is not supported", from.T)
	}
	for i := range from.Values {
		if from.Values[i] != to.Values[i] {
			return fmt.Errorf("replacing or reordering enum (%q) value is not supported: %q != %q", to.T, to.Values, from.Values)
		}
	}
	name := s.enumIdent(t.Schema, from)
	if prev, ok := s.altered[name]; ok {
		if !sqlx.ValuesEqual(prev.Values, to.Values) {
			return fmt.Errorf("enum type %s has inconsistent desired state: %q != %q", name, prev.Values, to.Values)
		}
		return nil
	}
	s.altered[name] = to
	for _, v := range to.Values[len(from.Values):] {
		s.append(&migrate.Change{
			Cmd:     s.Build("ALTER TYPE").P(name, "ADD VALUE", quote(v)).String(),
			Comment: fmt.Sprintf("add value to enum type: %q", from.T),
		})
	}
	return nil
}

func (s *state) enumExists(ctx context.Context, ns *schema.Schema, e *schema.EnumType) (bool, error) {
	query, args := `SELECT * FROM pg_type t JOIN pg_namespace n on t.typnamespace = n.oid WHERE t.typname = $1 AND t.typtype = 'e'`, []any{e.T}
	if es := s.enumSchema(ns, e); es != "" {
		query += " AND n.nspname = $2"
		args = append(args, es)
	}
	rows, err := s.QueryContext(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("check enum existence: %w", err)
	}
	defer rows.Close()
	return rows.Next(), rows.Err()
}

// mayDropEnum drops dangling enum types form the schema.
func (s *state) mayDropEnum(alter *alterChange, ns *schema.Schema, e *schema.EnumType) error {
	name := s.enumIdent(ns, e)
	if _, ok := s.dropped[name]; ok {
		return nil
	}
	schemas := []*schema.Schema{ns}
	// In case there is a realm attached, traverse the entire tree.
	if ns.Realm != nil && len(ns.Realm.Schemas) > 0 {
		schemas = ns.Realm.Schemas
	}
	for i := range schemas {
		for _, t := range schemas[i].Tables {
			for _, c := range t.Columns {
				e1, ok := hasEnumType(c)
				// Although we search in siblings schemas, use the
				// table's one for building the enum identifier.
				if ok && s.enumIdent(ns, e1) == name {
					return nil
				}
			}
		}
	}
	s.dropped[name] = e
	create, drop := s.createDropEnum(ns, e)
	alter.after = append(alter.after, &migrate.Change{
		Cmd:     drop,
		Reverse: create,
		Comment: fmt.Sprintf("drop enum type %q", e.T),
	})
	return nil
}

func (s *state) addIndexes(t *schema.Table, indexes ...*schema.Index) {
	for _, idx := range indexes {
		b := s.Build("CREATE")
		if idx.Unique {
			b.P("UNIQUE")
		}
		b.P("INDEX")
		if c := (Concurrently{}); sqlx.Has(idx.Attrs, &c) {
			b.P("CONCURRENTLY")
		}
		if idx.Name != "" {
			b.Ident(idx.Name)
		}
		b.P("ON").Table(t)
		s.index(b, idx)
		s.append(&migrate.Change{
			Cmd:     b.String(),
			Comment: fmt.Sprintf("create index %q to table: %q", idx.Name, t.Name),
			Reverse: func() string {
				b := s.Build("DROP INDEX")
				if c := (Concurrently{}); sqlx.Has(idx.Attrs, &c) {
					b.P("CONCURRENTLY")
				}
				// Unlike MySQL, the DROP command is not attached to ALTER TABLE.
				// Therefore, we print indexes with their qualified name, because
				// the connection that executes the statements may not be attached
				// to this schema.
				if t.Schema != nil {
					b.WriteString(s.schemaPrefix(t.Schema))
				}
				b.Ident(idx.Name)
				return b.String()
			}(),
		})
	}
}

func (s *state) column(b *sqlx.Builder, t *schema.Table, c *schema.Column) error {
	f, err := s.formatType(t, c)
	if err != nil {
		return err
	}
	b.Ident(c.Name).P(f)
	if !c.Type.Null {
		b.P("NOT")
	} else if t, ok := c.Type.Type.(*SerialType); ok {
		return fmt.Errorf("NOT NULL constraint is required for %s column %q", t.T, c.Name)
	}
	b.P("NULL")
	s.columnDefault(b, c)
	for _, attr := range c.Attrs {
		switch a := attr.(type) {
		case *schema.Comment:
		case *schema.Collation:
			b.P("COLLATE").Ident(a.V)
		case *Identity, *schema.GeneratedExpr:
			// Handled below.
		default:
			return fmt.Errorf("unexpected column attribute: %T", attr)
		}
	}
	switch hasI, hasX := sqlx.Has(c.Attrs, &Identity{}), sqlx.Has(c.Attrs, &schema.GeneratedExpr{}); {
	case hasI && hasX:
		return fmt.Errorf("both identity and generation expression specified for column %q", c.Name)
	case hasI:
		id, _ := identity(c.Attrs)
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
	case hasX:
		x := &schema.GeneratedExpr{}
		sqlx.Has(c.Attrs, x)
		b.P("GENERATED ALWAYS AS", sqlx.MayWrap(x.Expr), "STORED")
	}
	return nil
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

func (s *state) indexParts(b *sqlx.Builder, parts []*schema.IndexPart) {
	b.Wrap(func(b *sqlx.Builder) {
		b.MapComma(parts, func(i int, b *sqlx.Builder) {
			switch part := parts[i]; {
			case part.C != nil:
				b.Ident(part.C.Name)
			case part.X != nil:
				b.WriteString(sqlx.MayWrap(part.X.(*schema.RawExpr).X))
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
	if c := (IndexInclude{}); sqlx.Has(idx.Attrs, &c) {
		b.P("INCLUDE")
		b.Wrap(func(b *sqlx.Builder) {
			b.MapComma(c.Columns, func(i int, b *sqlx.Builder) {
				b.Ident(c.Columns[i].Name)
			})
		})
	}
	if p, ok := indexStorageParams(idx.Attrs); ok {
		b.P("WITH")
		b.Wrap(func(b *sqlx.Builder) {
			var parts []string
			if p.AutoSummarize {
				parts = append(parts, "autosummarize = true")
			}
			if p.PagesPerRange != 0 && p.PagesPerRange != defaultPagePerRange {
				parts = append(parts, fmt.Sprintf("pages_per_range = %d", p.PagesPerRange))
			}
			b.WriteString(strings.Join(parts, ", "))
		})
	}
	if p := (IndexPredicate{}); sqlx.Has(idx.Attrs, &p) {
		b.P("WHERE").P(p.P)
	}
	for _, attr := range idx.Attrs {
		switch attr.(type) {
		case *schema.Comment, *ConType, *IndexType, *IndexInclude, *Concurrently, *IndexPredicate, *IndexStorageParams:
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
func (s *state) Build(phrases ...string) *sqlx.Builder {
	b := &sqlx.Builder{QuoteChar: '"', Schema: s.SchemaQualifier}
	return b.P(phrases...)
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
		// with it. This is true for multi-columns indexes as well.
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
	if c.Name != "" {
		b.P("CONSTRAINT").Ident(c.Name)
	}
	b.P("CHECK", sqlx.MayWrap(c.Expr))
	if sqlx.Has(c.Attrs, &NoInherit{}) {
		b.P("NO INHERIT")
	}
}

// isUniqueConstraint reports if the index is a valid UNIQUE constraint.
func isUniqueConstraint(i *schema.Index) bool {
	if c := (ConType{}); !sqlx.Has(i.Attrs, &c) || !c.IsUnique() || !i.Unique {
		return false
	}
	// UNIQUE constraint cannot use functional indexes,
	// and all its parts must have the default sort ordering.
	for _, p := range i.Parts {
		if p.X != nil || p.Desc {
			return false
		}
	}
	for _, a := range i.Attrs {
		switch a := a.(type) {
		// UNIQUE constraints must have BTREE type indexes.
		case *IndexType:
			if strings.ToUpper(a.T) != IndexTypeBTree {
				return false
			}
		// Partial indexes are not allowed.
		case *IndexPredicate:
			return false
		}
	}
	return true
}

func quote(s string) string {
	if sqlx.IsQuoted(s, '\'') {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func (s *state) createDropEnum(sc *schema.Schema, e *schema.EnumType) (string, string) {
	name := s.enumIdent(sc, e)
	return s.Build("CREATE TYPE").
			P(name, "AS ENUM").
			Wrap(func(b *sqlx.Builder) {
				b.MapComma(e.Values, func(i int, b *sqlx.Builder) {
					b.WriteString(quote(e.Values[i]))
				})
			}).
			String(),
		s.Build("DROP TYPE").P(name).String()
}

func (s *state) enumIdent(ns *schema.Schema, e *schema.EnumType) string {
	es := s.enumSchema(ns, e)
	if es != "" {
		return fmt.Sprintf("%q.%q", es, e.T)
	}
	return strconv.Quote(e.T)
}

func (s *state) enumSchema(ns *schema.Schema, e *schema.EnumType) (es string) {
	switch {
	// In case the plan uses a specific schema qualifier.
	case s.SchemaQualifier != nil:
		es = *s.SchemaQualifier
	// Enum schema has higher precedence.
	case e.Schema != nil:
		es = e.Schema.Name
	// Fallback to table schema if exists.
	case ns != nil:
		es = ns.Name
	}
	return
}

// schemaPrefix returns the schema prefix based on the planner config.
func (s *state) schemaPrefix(ns *schema.Schema) string {
	switch {
	case s.SchemaQualifier != nil:
		// In case the qualifier is empty, ignore.
		if *s.SchemaQualifier != "" {
			return fmt.Sprintf("%q.", *s.SchemaQualifier)
		}
	case ns != nil && ns.Name != "":
		return fmt.Sprintf("%q.", ns.Name)
	}
	return ""
}

// formatType formats the type but takes into account the qualifier.
func (s *state) formatType(t *schema.Table, c *schema.Column) (string, error) {
	switch tt := c.Type.Type.(type) {
	case *schema.EnumType:
		return s.enumIdent(t.Schema, tt), nil
	case *ArrayType:
		if e, ok := tt.Type.(*schema.EnumType); ok {
			return s.enumIdent(t.Schema, e) + "[]", nil
		}
	}
	return FormatType(c.Type.Type)
}

func hasEnumType(c *schema.Column) (*schema.EnumType, bool) {
	switch t := c.Type.Type.(type) {
	case *schema.EnumType:
		return t, true
	case *ArrayType:
		if e, ok := t.Type.(*schema.EnumType); ok {
			return e, true
		}
	}
	return nil, false
}
