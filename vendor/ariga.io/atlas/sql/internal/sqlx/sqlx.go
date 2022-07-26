// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlx

import (
	"bytes"
	"database/sql"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/schema"
)

// ValidString reports if the given string is not null and valid.
func ValidString(s sql.NullString) bool {
	return s.Valid && s.String != "" && strings.ToLower(s.String) != "null"
}

// ScanOne scans one record and closes the rows at the end.
func ScanOne(rows *sql.Rows, dest ...interface{}) error {
	defer rows.Close()
	if !rows.Next() {
		return sql.ErrNoRows
	}
	if err := rows.Scan(dest...); err != nil {
		return err
	}
	return rows.Close()
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

// VersionPermutations returns permutations of the dialect version sorted
// from coarse to fine grained. For example:
//
//   VersionPermutations("mysql", "1.2.3") => ["mysql", "mysql 1", "mysql 1.2", "mysql 1.2.3"]
//
// VersionPermutations will split the version number by ".", " ", "-" or "_", and rejoin them
// with ".". The output slice can be used by drivers to generate a list of permutations
// for searching for relevant overrides in schema element specs.
func VersionPermutations(dialect, version string) []string {
	parts := strings.FieldsFunc(version, func(r rune) bool {
		return r == '.' || r == ' ' || r == '-' || r == '_'
	})
	names := []string{dialect}
	for i := range parts {
		version := strings.Join(parts[0:i+1], ".")
		names = append(names, dialect+" "+version)
	}
	return names
}

// A Builder provides a syntactic sugar API for writing SQL statements.
type Builder struct {
	bytes.Buffer
	QuoteChar byte
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
	if t.Schema != nil {
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
func (b *Builder) MapComma(x interface{}, f func(i int, b *Builder)) *Builder {
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
func (b *Builder) MapCommaErr(x interface{}, f func(i int, b *Builder) error) error {
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
		Buffer:    *bytes.NewBufferString(b.String()),
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

// IsQuoted reports if the given string is quoted with one of the given quotes (e.g. '\'', '"', '`').
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
