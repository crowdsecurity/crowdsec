// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlx

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/schema"
)

type (
	// ExecQueryCloser is the interface that groups
	// Close with the schema.ExecQuerier methods.
	ExecQueryCloser interface {
		schema.ExecQuerier
		io.Closer
	}
	nopCloser struct {
		schema.ExecQuerier
	}
)

// Close implements the io.Closer interface.
func (nopCloser) Close() error { return nil }

// SingleConn returns a closable single connection from the given ExecQuerier.
// If the ExecQuerier is already bound to a single connection (e.g. Tx, Conn),
// the connection will return as-is with a NopCloser.
func SingleConn(ctx context.Context, conn schema.ExecQuerier) (ExecQueryCloser, error) {
	// A standard sql.DB or a wrapper of it.
	if opener, ok := conn.(interface {
		Conn(context.Context) (*sql.Conn, error)
	}); ok {
		return opener.Conn(ctx)
	}
	// Tx and Conn are bounded to a single connection.
	// We use sql/driver.Tx to cover also custom Tx structs.
	_, ok1 := conn.(driver.Tx)
	_, ok2 := conn.(*sql.Conn)
	if ok1 || ok2 {
		return nopCloser{ExecQuerier: conn}, nil
	}
	return nil, fmt.Errorf("cannot obtain a single connection from %T", conn)
}

// ValidString reports if the given string is not null and valid.
func ValidString(s sql.NullString) bool {
	return s.Valid && s.String != "" && strings.ToLower(s.String) != "null"
}

// ScanOne scans one record and closes the rows at the end.
func ScanOne(rows *sql.Rows, dest ...any) error {
	defer rows.Close()
	if !rows.Next() {
		return sql.ErrNoRows
	}
	if err := rows.Scan(dest...); err != nil {
		return err
	}
	return rows.Close()
}

// ScanNullBool scans one sql.NullBool record and closes the rows at the end.
func ScanNullBool(rows *sql.Rows) (sql.NullBool, error) {
	var b sql.NullBool
	return b, ScanOne(rows, &b)
}

// ScanStrings scans sql.Rows into a slice of strings and closes it at the end.
func ScanStrings(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var vs []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		vs = append(vs, v)
	}
	return vs, nil
}

// SchemaFKs scans the rows and adds the foreign-key to the schema table.
// Reference elements are added as stubs and should be linked manually by the
// caller.
func SchemaFKs(s *schema.Schema, rows *sql.Rows) error {
	for rows.Next() {
		var name, table, column, tSchema, refTable, refColumn, refSchema, updateRule, deleteRule string
		if err := rows.Scan(&name, &table, &column, &tSchema, &refTable, &refColumn, &refSchema, &updateRule, &deleteRule); err != nil {
			return err
		}
		t, ok := s.Table(table)
		if !ok {
			return fmt.Errorf("table %q was not found in schema", table)
		}
		fk, ok := t.ForeignKey(name)
		if !ok {
			fk = &schema.ForeignKey{
				Symbol:   name,
				Table:    t,
				RefTable: t,
				OnDelete: schema.ReferenceOption(deleteRule),
				OnUpdate: schema.ReferenceOption(updateRule),
			}
			switch {
			case refTable == table:
			case tSchema == refSchema:
				if fk.RefTable, ok = s.Table(refTable); !ok {
					fk.RefTable = &schema.Table{Name: refTable, Schema: s}
				}
			case tSchema != refSchema:
				fk.RefTable = &schema.Table{Name: refTable, Schema: &schema.Schema{Name: refSchema}}
			}
			t.ForeignKeys = append(t.ForeignKeys, fk)
		}
		c, ok := t.Column(column)
		if !ok {
			return fmt.Errorf("column %q was not found for fk %q", column, fk.Symbol)
		}
		// Rows are ordered by ORDINAL_POSITION that specifies
		// the position of the column in the FK definition.
		if _, ok := fk.Column(c.Name); !ok {
			fk.Columns = append(fk.Columns, c)
			c.ForeignKeys = append(c.ForeignKeys, fk)
		}
		// Stub referenced columns or link if it's a self-reference.
		var rc *schema.Column
		if fk.Table != fk.RefTable {
			rc = &schema.Column{Name: refColumn}
		} else if c, ok := t.Column(refColumn); ok {
			rc = c
		} else {
			return fmt.Errorf("referenced column %q was not found for fk %q", refColumn, fk.Symbol)
		}
		if _, ok := fk.RefColumn(rc.Name); !ok {
			fk.RefColumns = append(fk.RefColumns, rc)
		}
	}
	return nil
}

// LinkSchemaTables links foreign-key stub tables/columns to actual elements.
func LinkSchemaTables(schemas []*schema.Schema) {
	byName := make(map[string]map[string]*schema.Table)
	for _, s := range schemas {
		byName[s.Name] = make(map[string]*schema.Table)
		for _, t := range s.Tables {
			t.Schema = s
			byName[s.Name][t.Name] = t
		}
	}
	for _, s := range schemas {
		for _, t := range s.Tables {
			for _, fk := range t.ForeignKeys {
				rs, ok := byName[fk.RefTable.Schema.Name]
				if !ok {
					continue
				}
				ref, ok := rs[fk.RefTable.Name]
				if !ok {
					continue
				}
				fk.RefTable = ref
				for i, c := range fk.RefColumns {
					rc, ok := ref.Column(c.Name)
					if ok {
						fk.RefColumns[i] = rc
					}
				}
			}
		}
	}
}

// ValuesEqual checks if the 2 string slices are equal (including their order).
func ValuesEqual(v1, v2 []string) bool {
	if len(v1) != len(v2) {
		return false
	}
	for i := range v1 {
		if v1[i] != v2[i] {
			return false
		}
	}
	return true
}

// ModeInspectSchema returns the InspectMode or its default.
func ModeInspectSchema(o *schema.InspectOptions) schema.InspectMode {
	if o == nil || o.Mode == 0 {
		return schema.InspectSchemas | schema.InspectTables
	}
	return o.Mode
}

// ModeInspectRealm returns the InspectMode or its default.
func ModeInspectRealm(o *schema.InspectRealmOption) schema.InspectMode {
	if o == nil || o.Mode == 0 {
		return schema.InspectSchemas | schema.InspectTables
	}
	return o.Mode
}

// A Builder provides a syntactic sugar API for writing SQL statements.
type Builder struct {
	bytes.Buffer
	QuoteChar byte    // quoting identifiers
	Schema    *string // schema qualifier
}

// P writes a list of phrases to the builder separated and
// suffixed with whitespace.
func (b *Builder) P(phrases ...string) *Builder {
	for _, p := range phrases {
		if p == "" {
			continue
		}
		if b.Len() > 0 && b.lastByte() != ' ' && b.lastByte() != '(' {
			b.WriteByte(' ')
		}
		b.WriteString(p)
		if p[len(p)-1] != ' ' {
			b.WriteByte(' ')
		}
	}
	return b
}

// Ident writes the given string quoted as an SQL identifier.
func (b *Builder) Ident(s string) *Builder {
	if s != "" {
		b.WriteByte(b.QuoteChar)
		b.WriteString(s)
		b.WriteByte(b.QuoteChar)
		b.WriteByte(' ')
	}
	return b
}

// Table writes the table identifier to the builder, prefixed
// with the schema name if exists.
func (b *Builder) Table(t *schema.Table) *Builder {
	switch {
	// Custom qualifier.
	case b.Schema != nil:
		// Empty means skip prefix.
		if *b.Schema != "" {
			b.Ident(*b.Schema)
			b.rewriteLastByte('.')
		}
	// Default schema qualifier.
	case t.Schema != nil && t.Schema.Name != "":
		b.Ident(t.Schema.Name)
		b.rewriteLastByte('.')
	}
	b.Ident(t.Name)
	return b
}

// Comma writes a comma in case the buffer is not empty, or
// replaces the last char if it is a whitespace.
func (b *Builder) Comma() *Builder {
	switch {
	case b.Len() == 0:
	case b.lastByte() == ' ':
		b.rewriteLastByte(',')
		b.WriteByte(' ')
	default:
		b.WriteString(", ")
	}
	return b
}

// MapComma maps the slice x using the function f and joins the result with
// a comma separating between the written elements.
func (b *Builder) MapComma(x any, f func(i int, b *Builder)) *Builder {
	s := reflect.ValueOf(x)
	for i := 0; i < s.Len(); i++ {
		if i > 0 {
			b.Comma()
		}
		f(i, b)
	}
	return b
}

// MapCommaErr is like MapComma, but returns an error if f returns an error.
func (b *Builder) MapCommaErr(x any, f func(i int, b *Builder) error) error {
	s := reflect.ValueOf(x)
	for i := 0; i < s.Len(); i++ {
		if i > 0 {
			b.Comma()
		}
		if err := f(i, b); err != nil {
			return err
		}
	}
	return nil
}

// Wrap wraps the written string with parentheses.
func (b *Builder) Wrap(f func(b *Builder)) *Builder {
	b.WriteByte('(')
	f(b)
	if b.lastByte() != ' ' {
		b.WriteByte(')')
	} else {
		b.rewriteLastByte(')')
	}
	return b
}

// Clone returns a duplicate of the builder.
func (b *Builder) Clone() *Builder {
	return &Builder{
		QuoteChar: b.QuoteChar,
		Buffer:    *bytes.NewBufferString(b.Buffer.String()),
	}
}

// String overrides the Buffer.String method and ensure no spaces pad the returned statement.
func (b *Builder) String() string {
	return strings.TrimSpace(b.Buffer.String())
}

func (b *Builder) lastByte() byte {
	if b.Len() == 0 {
		return 0
	}
	buf := b.Buffer.Bytes()
	return buf[len(buf)-1]
}

func (b *Builder) rewriteLastByte(c byte) {
	if b.Len() == 0 {
		return
	}
	buf := b.Buffer.Bytes()
	buf[len(buf)-1] = c
}

// IsQuoted reports if the given string is quoted with one of the given quotes (e.g. ', ", `).
func IsQuoted(s string, q ...byte) bool {
	for i := range q {
		if l, r := strings.IndexByte(s, q[i]), strings.LastIndexByte(s, q[i]); l < r && l == 0 && r == len(s)-1 {
			return true
		}
	}
	return false
}

// IsLiteralBool reports if the given string is a valid literal bool.
func IsLiteralBool(s string) bool {
	_, err := strconv.ParseBool(s)
	return err == nil
}

// IsLiteralNumber reports if the given string is a literal number.
func IsLiteralNumber(s string) bool {
	// Hex digits.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		// Some databases allow odd length hex string.
		_, err := strconv.ParseUint(s[2:], 16, 64)
		return err == nil
	}
	// Digits with optional exponent.
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// DefaultValue returns the string represents the DEFAULT of a column.
func DefaultValue(c *schema.Column) (string, bool) {
	switch x := c.Default.(type) {
	case nil:
		return "", false
	case *schema.Literal:
		return x.V, true
	case *schema.RawExpr:
		return x.X, true
	default:
		panic(fmt.Sprintf("unexpected default value type: %T", x))
	}
}

// MayWrap ensures the given string is wrapped with parentheses.
// Used by the different drivers to turn strings valid expressions.
func MayWrap(s string) string {
	n := len(s) - 1
	if len(s) < 2 || s[0] != '(' || s[n] != ')' || !balanced(s[1:n]) {
		return "(" + s + ")"
	}
	return s
}

func balanced(expr string) bool {
	return ExprLastIndex(expr) == len(expr)-1
}

// ExprLastIndex scans the first expression in the given string until
// its end and returns its last index.
func ExprLastIndex(expr string) int {
	var l, r int
	for i := 0; i < len(expr); i++ {
	Top:
		switch expr[i] {
		case '(':
			l++
		case ')':
			r++
		// String or identifier.
		case '\'', '"', '`':
			for j := i + 1; j < len(expr); j++ {
				switch expr[j] {
				case '\\':
					j++
				case expr[i]:
					i = j
					break Top
				}
			}
			// Unexpected EOS.
			return -1
		}
		// Balanced parens and we reached EOS or a terminator.
		if l == r && (i == len(expr)-1 || expr[i+1] == ',') {
			return i
		} else if r > l {
			return -1
		}
	}
	return -1
}

// ReverseChanges reverses the order of the changes.
func ReverseChanges(c []schema.Change) {
	for i, n := 0, len(c); i < n/2; i++ {
		c[i], c[n-i-1] = c[n-i-1], c[i]
	}
}

// P returns a pointer to v.
func P[T any](v T) *T {
	return &v
}

// V returns the value p is pointing to.
// If p is nil, the zero value is returned.
func V[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return
}
