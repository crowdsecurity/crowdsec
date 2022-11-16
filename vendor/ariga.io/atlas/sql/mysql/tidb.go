// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package mysql

import (
	"context"
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/schema"
)

type (
	// tplanApply decorates MySQL planApply.
	tplanApply struct{ planApply }
	// tdiff decorates MySQL diff.
	tdiff struct{ diff }
	// tinspect decorates MySQL inspect.
	tinspect struct{ inspect }
)

// priority computes the priority of each change.
//
// TiDB does not support multischema ALTERs (i.e. multiple changes in a single ALTER statement).
// Therefore, we have to break down each alter. This function helps order the ALTERs so they work.
// e.g. priority gives precedence to DropForeignKey over DropColumn, because a column cannot be
// dropped if its foreign key was not dropped before.
func priority(change schema.Change) int {
	switch c := change.(type) {
	case *schema.ModifyTable:
		// each modifyTable should have a single change since we apply `flat` before we sort.
		return priority(c.Changes[0])
	case *schema.ModifySchema:
		// each modifyTable should have a single change since we apply `flat` before we sort.
		return priority(c.Changes[0])
	case *schema.AddColumn:
		return 1
	case *schema.DropIndex, *schema.DropForeignKey, *schema.DropAttr, *schema.DropCheck:
		return 2
	case *schema.ModifyIndex, *schema.ModifyForeignKey:
		return 3
	default:
		return 4
	}
}

// flat takes a list of changes and breaks them down to single atomic changes (e.g: no ModifyTable
// with multiple AddColumn inside it). Note that, the only "changes" that include sub-changes are
// `ModifyTable` and `ModifySchema`.
func flat(changes []schema.Change) []schema.Change {
	var flat []schema.Change
	for _, change := range changes {
		switch m := change.(type) {
		case *schema.ModifyTable:
			for _, c := range m.Changes {
				flat = append(flat, &schema.ModifyTable{
					T:       m.T,
					Changes: []schema.Change{c},
				})
			}
		case *schema.ModifySchema:
			for _, c := range m.Changes {
				flat = append(flat, &schema.ModifySchema{
					S:       m.S,
					Changes: []schema.Change{c},
				})
			}
		default:
			flat = append(flat, change)
		}
	}
	return flat
}

// PlanChanges returns a migration plan for the given schema changes.
func (p *tplanApply) PlanChanges(ctx context.Context, name string, changes []schema.Change, opts ...migrate.PlanOption) (*migrate.Plan, error) {
	fc := flat(changes)
	sort.SliceStable(fc, func(i, j int) bool {
		return priority(fc[i]) < priority(fc[j])
	})
	s := &state{
		conn: p.conn,
		Plan: migrate.Plan{
			Name: name,
			// A plan is reversible, if all
			// its changes are reversible.
			Reversible:    true,
			Transactional: false,
		},
	}
	for _, c := range fc {
		// Use the planner of MySQL with each "atomic" change.
		plan, err := p.planApply.PlanChanges(ctx, name, []schema.Change{c}, opts...)
		if err != nil {
			return nil, err
		}
		if !plan.Reversible {
			s.Plan.Reversible = false
		}
		s.Plan.Changes = append(s.Plan.Changes, plan.Changes...)
	}
	return &s.Plan, nil
}

func (p *tplanApply) ApplyChanges(ctx context.Context, changes []schema.Change, opts ...migrate.PlanOption) error {
	return sqlx.ApplyChanges(ctx, changes, p, opts...)
}

func (i *tinspect) InspectSchema(ctx context.Context, name string, opts *schema.InspectOptions) (*schema.Schema, error) {
	s, err := i.inspect.InspectSchema(ctx, name, opts)
	if err != nil {
		return nil, err
	}
	return i.patchSchema(ctx, s)
}

func (i *tinspect) InspectRealm(ctx context.Context, opts *schema.InspectRealmOption) (*schema.Realm, error) {
	r, err := i.inspect.InspectRealm(ctx, opts)
	if err != nil {
		return nil, err
	}
	for _, s := range r.Schemas {
		if _, err := i.patchSchema(ctx, s); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (i *tinspect) patchSchema(ctx context.Context, s *schema.Schema) (*schema.Schema, error) {
	for _, t := range s.Tables {
		var createStmt CreateStmt
		if ok := sqlx.Has(t.Attrs, &createStmt); !ok {
			if err := i.createStmt(ctx, t); err != nil {
				return nil, err
			}
		}
		if err := i.setCollate(t); err != nil {
			return nil, err
		}
		if err := i.setFKs(s, t); err != nil {
			return nil, err
		}
		if err := i.setAutoIncrement(t); err != nil {
			return nil, err
		}
		for _, c := range t.Columns {
			i.patchColumn(ctx, c)
		}
	}
	return s, nil
}

func (i *tinspect) patchColumn(_ context.Context, c *schema.Column) {
	_, ok := c.Type.Type.(*BitType)
	if !ok {
		return
	}
	// TiDB has a bug where it does not format bit default value correctly.
	if lit, ok := c.Default.(*schema.Literal); ok && !strings.HasPrefix(lit.V, "b'") {
		lit.V = bytesToBitLiteral([]byte(lit.V))
	}
}

// bytesToBitLiteral converts a bytes to MySQL bit literal.
// e.g. []byte{4} -> b'100', []byte{2,1} -> b'1000000001'.
// See: https://github.com/pingcap/tidb/issues/32655.
func bytesToBitLiteral(b []byte) string {
	bytes := make([]byte, 8)
	for i := 0; i < len(b); i++ {
		bytes[8-len(b)+i] = b[i]
	}
	val := binary.BigEndian.Uint64(bytes)
	return fmt.Sprintf("b'%b'", val)
}

// e.g. CONSTRAINT "" FOREIGN KEY ("foo_id") REFERENCES "foo" ("id").
var reFK = regexp.MustCompile("(?i)CONSTRAINT\\s+[\"`]*(\\w+)[\"`]*\\s+FOREIGN\\s+KEY\\s*\\(([,\"` \\w]+)\\)\\s+REFERENCES\\s+[\"`]*(\\w+)[\"`]*\\s*\\(([,\"` \\w]+)\\).*")
var reActions = regexp.MustCompile(fmt.Sprintf("(?i)(ON)\\s+(UPDATE|DELETE)\\s+(%s|%s|%s|%s|%s)", schema.NoAction, schema.Restrict, schema.SetNull, schema.SetDefault, schema.Cascade))

func (i *tinspect) setFKs(s *schema.Schema, t *schema.Table) error {
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE TABLE statment in attribuets for %q", t.Name)
	}
	for _, m := range reFK.FindAllStringSubmatch(c.S, -1) {
		if len(m) != 5 {
			return fmt.Errorf("unexpected number of matches for a table constraint: %q", m)
		}
		stmt, ctName, clmns, refTableName, refClmns := m[0], m[1], m[2], m[3], m[4]
		fk := &schema.ForeignKey{
			Symbol: ctName,
			Table:  t,
		}
		actions := reActions.FindAllStringSubmatch(stmt, 2)
		for _, actionMatches := range actions {
			actionType, actionOp := actionMatches[2], actionMatches[3]
			switch actionType {
			case "UPDATE":
				fk.OnUpdate = schema.ReferenceOption(actionOp)
			case "DELETE":
				fk.OnDelete = schema.ReferenceOption(actionOp)
			default:
				return fmt.Errorf("action type %s is none of 'UPDATE'/'DELETE'", actionType)
			}
		}
		refTable, ok := s.Table(refTableName)
		if !ok {
			return fmt.Errorf("couldn't resolve ref table %s on ", m[3])
		}
		fk.RefTable = refTable
		for _, c := range columns(s, clmns) {
			column, ok := t.Column(c)
			if !ok {
				return fmt.Errorf("column %q was not found for fk %q", c, ctName)
			}
			fk.Columns = append(fk.Columns, column)
		}
		for _, c := range columns(s, refClmns) {
			column, ok := refTable.Column(c)
			if !ok {
				return fmt.Errorf("ref column %q was not found for fk %q", c, ctName)
			}
			fk.RefColumns = append(fk.RefColumns, column)
		}
		t.ForeignKeys = append(t.ForeignKeys, fk)
	}
	return nil
}

// columns from the matched regex above.
func columns(schema *schema.Schema, s string) []string {
	names := strings.Split(s, ",")
	for i := range names {
		names[i] = strings.Trim(strings.TrimSpace(names[i]), "`\"")
	}
	return names
}

// e.g CHARSET=utf8mb4 COLLATE=utf8mb4_bin
var reColl = regexp.MustCompile(`(?i)CHARSET\s*=\s*(\w+)\s*COLLATE\s*=\s*(\w+)`)

// setCollate extracts the updated Collation from CREATE TABLE statement.
func (i *tinspect) setCollate(t *schema.Table) error {
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE TABLE statement in attributes for %q", t.Name)
	}
	matches := reColl.FindStringSubmatch(c.S)
	if len(matches) != 3 {
		return fmt.Errorf("missing COLLATE and/or CHARSET information on CREATE TABLE statement for %q", t.Name)
	}
	t.SetCharset(matches[1])
	t.SetCollation(matches[2])
	return nil
}

// setCollate extracts the updated Collation from CREATE TABLE statement.
func (i *tinspect) setAutoIncrement(t *schema.Table) error {
	// patch only it is set (set falsely to '1' due to this bug:https://github.com/pingcap/tidb/issues/24702).
	ai := &AutoIncrement{}
	if !sqlx.Has(t.Attrs, ai) {
		return nil
	}
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE TABLE statement in attributes for %q", t.Name)
	}
	matches := reAutoinc.FindStringSubmatch(c.S)
	if len(matches) != 2 {
		return nil
	}
	v, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		return err
	}
	ai.V = v
	schema.ReplaceOrAppend(&t.Attrs, ai)
	return nil
}
