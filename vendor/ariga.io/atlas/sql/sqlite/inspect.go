// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/schema"
)

// A diff provides a PostgreSQL implementation for schema.Inspector.
type inspect struct{ conn }

var _ schema.Inspector = (*inspect)(nil)

// InspectRealm returns schema descriptions of all resources in the given realm.
func (i *inspect) InspectRealm(ctx context.Context, opts *schema.InspectRealmOption) (*schema.Realm, error) {
	schemas, err := i.databases(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(schemas) > 1 {
		return nil, fmt.Errorf("sqlite: multiple database files are not supported by the driver. got: %d", len(schemas))
	}
	realm := &schema.Realm{Schemas: schemas}
	for _, s := range schemas {
		tables, err := i.tables(ctx, nil)
		if err != nil {
			return nil, err
		}
		for _, t := range tables {
			t.Schema = s
			t, err := i.inspectTable(ctx, t)
			if err != nil {
				return nil, err
			}
			s.Tables = append(s.Tables, t)
		}
		s.Realm = realm
	}
	sqlx.LinkSchemaTables(realm.Schemas)
	return realm, nil
}

// InspectSchema returns schema descriptions of the tables in the given schema.
// If the schema name is empty, the "main" database is used.
func (i *inspect) InspectSchema(ctx context.Context, name string, opts *schema.InspectOptions) (*schema.Schema, error) {
	if name == "" {
		name = mainFile
	}
	schemas, err := i.databases(ctx, &schema.InspectRealmOption{
		Schemas: []string{name},
	})
	if err != nil {
		return nil, err
	}
	if len(schemas) == 0 {
		return nil, &schema.NotExistError{
			Err: fmt.Errorf("sqlite: schema %q was not found", name),
		}
	}
	tables, err := i.tables(ctx, opts)
	if err != nil {
		return nil, err
	}
	s := schemas[0]
	for _, t := range tables {
		t.Schema = s
		t, err := i.inspectTable(ctx, t)
		if err != nil {
			return nil, err
		}
		s.Tables = append(s.Tables, t)
	}
	sqlx.LinkSchemaTables(schemas)
	s.Realm = &schema.Realm{Schemas: schemas}
	return s, nil
}

func (i *inspect) inspectTable(ctx context.Context, t *schema.Table) (*schema.Table, error) {
	if err := i.columns(ctx, t); err != nil {
		return nil, err
	}
	if err := i.indexes(ctx, t); err != nil {
		return nil, err
	}
	if err := i.fks(ctx, t); err != nil {
		return nil, err
	}
	if err := fillChecks(t); err != nil {
		return nil, err
	}
	return t, nil
}

// columns queries and appends the columns of the given table.
func (i *inspect) columns(ctx context.Context, t *schema.Table) error {
	rows, err := i.QueryContext(ctx, fmt.Sprintf(columnsQuery, t.Name))
	if err != nil {
		return fmt.Errorf("sqlite: querying %q columns: %w", t.Name, err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := i.addColumn(t, rows); err != nil {
			return fmt.Errorf("sqlite: %w", err)
		}
	}
	return autoinc(t)
}

// addColumn scans the current row and adds a new column from it to the table.
func (i *inspect) addColumn(t *schema.Table, rows *sql.Rows) error {
	var (
		nullable, primary   bool
		name, typ, defaults sql.NullString
		err                 error
	)
	if err = rows.Scan(&name, &typ, &nullable, &defaults, &primary); err != nil {
		return err
	}
	c := &schema.Column{
		Name: name.String,
		Type: &schema.ColumnType{
			Raw:  typ.String,
			Null: nullable,
		},
	}
	c.Type.Type, err = ParseType(typ.String)
	if err != nil {
		return err
	}
	if sqlx.ValidString(defaults) {
		c.Default = defaultExpr(defaults.String)
	}
	// TODO(a8m): extract collation from 'CREATE TABLE' statement.
	t.Columns = append(t.Columns, c)
	if primary {
		if t.PrimaryKey == nil {
			t.PrimaryKey = &schema.Index{
				Name:   "PRIMARY",
				Unique: true,
				Table:  t,
			}
		}
		// Columns are ordered by the `pk` field.
		t.PrimaryKey.Parts = append(t.PrimaryKey.Parts, &schema.IndexPart{
			C:     c,
			SeqNo: len(t.PrimaryKey.Parts) + 1,
		})
	}
	return nil
}

// indexes queries and appends the indexes of the given table.
func (i *inspect) indexes(ctx context.Context, t *schema.Table) error {
	rows, err := i.QueryContext(ctx, fmt.Sprintf(indexesQuery, t.Name))
	if err != nil {
		return fmt.Errorf("sqlite: querying %q indexes: %w", t.Name, err)
	}
	if err := i.addIndexes(t, rows); err != nil {
		return fmt.Errorf("sqlite: scan %q indexes: %w", t.Name, err)
	}
	for _, idx := range t.Indexes {
		if err := i.indexInfo(ctx, t, idx); err != nil {
			return err
		}
	}
	return nil
}

// addIndexes scans the rows and adds the indexes to the table.
func (i *inspect) addIndexes(t *schema.Table, rows *sql.Rows) error {
	defer rows.Close()
	for rows.Next() {
		var (
			uniq, partial      bool
			name, origin, stmt sql.NullString
		)
		if err := rows.Scan(&name, &uniq, &origin, &partial, &stmt); err != nil {
			return err
		}
		if origin.String == "pk" {
			continue
		}
		idx := &schema.Index{
			Name:   name.String,
			Unique: uniq,
			Table:  t,
			Attrs: []schema.Attr{
				&CreateStmt{S: stmt.String},
				&IndexOrigin{O: origin.String},
			},
		}
		if partial {
			i := strings.Index(stmt.String, "WHERE")
			if i == -1 {
				return fmt.Errorf("missing partial WHERE clause in: %s", stmt.String)
			}
			idx.Attrs = append(idx.Attrs, &IndexPredicate{
				P: strings.TrimSpace(stmt.String[i+5:]),
			})
		}
		t.Indexes = append(t.Indexes, idx)
	}
	return nil
}

func (i *inspect) indexInfo(ctx context.Context, t *schema.Table, idx *schema.Index) error {
	rows, err := i.QueryContext(ctx, fmt.Sprintf(indexColumnsQuery, idx.Name))
	if err != nil {
		return fmt.Errorf("sqlite: querying %q indexes: %w", t.Name, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			desc sql.NullBool
			name sql.NullString
		)
		if err := rows.Scan(&name, &desc); err != nil {
			return fmt.Errorf("sqlite: scanning index names: %w", err)
		}
		part := &schema.IndexPart{
			SeqNo: len(idx.Parts) + 1,
			Desc:  desc.Bool,
		}
		switch c, ok := t.Column(name.String); {
		case ok:
			part.C = c
		// NULL name indicates that the index-part is an expression and we
		// should extract it from the `CREATE INDEX` statement (not supported atm).
		case !sqlx.ValidString(name):
			part.X = &schema.RawExpr{X: "<unsupported>"}
		default:
			return fmt.Errorf("sqlite: column %q was not found for index %q", name.String, idx.Name)
		}
		idx.Parts = append(idx.Parts, part)
	}
	return nil
}

// fks queries and appends the foreign-keys of the given table.
func (i *inspect) fks(ctx context.Context, t *schema.Table) error {
	rows, err := i.QueryContext(ctx, fmt.Sprintf(fksQuery, t.Name))
	if err != nil {
		return fmt.Errorf("sqlite: querying %q foreign-keys: %w", t.Name, err)
	}
	if err := i.addFKs(t, rows); err != nil {
		return fmt.Errorf("sqlite: scan %q foreign-keys: %w", t.Name, err)
	}
	return fillConstName(t)
}

func (i *inspect) addFKs(t *schema.Table, rows *sql.Rows) error {
	ids := make(map[int]*schema.ForeignKey)
	for rows.Next() {
		var (
			id                                                  int
			column, refColumn, refTable, updateRule, deleteRule string
		)
		if err := rows.Scan(&id, &column, &refColumn, &refTable, &updateRule, &deleteRule); err != nil {
			return err
		}
		fk, ok := ids[id]
		if !ok {
			fk = &schema.ForeignKey{
				Symbol:   strconv.Itoa(id),
				Table:    t,
				RefTable: t,
				OnDelete: schema.ReferenceOption(deleteRule),
				OnUpdate: schema.ReferenceOption(updateRule),
			}
			if refTable != t.Name {
				fk.RefTable = &schema.Table{Name: refTable, Schema: &schema.Schema{Name: t.Schema.Name}}
			}
			ids[id] = fk
			t.ForeignKeys = append(t.ForeignKeys, fk)
		}
		c, ok := t.Column(column)
		if !ok {
			return fmt.Errorf("column %q was not found for fk %q", column, fk.Symbol)
		}
		// Rows are ordered by SEQ that specifies the
		// position of the column in the FK definition.
		if _, ok := fk.Column(c.Name); !ok {
			fk.Columns = append(fk.Columns, c)
			c.ForeignKeys = append(c.ForeignKeys, fk)
		}

		// Stub referenced columns or link if it is a self-reference.
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

// tableNames returns a list of all tables exist in the schema.
func (i *inspect) tables(ctx context.Context, opts *schema.InspectOptions) ([]*schema.Table, error) {
	var (
		args  []interface{}
		query = tablesQuery
	)
	if opts != nil && len(opts.Tables) > 0 {
		query += " AND name IN (" + strings.Repeat("?, ", len(opts.Tables)-1) + "?)"
		for _, s := range opts.Tables {
			args = append(args, s)
		}
	}
	rows, err := i.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: querying schema tables: %w", err)
	}
	defer rows.Close()
	var tables []*schema.Table
	for rows.Next() {
		var name, stmt string
		if err := rows.Scan(&name, &stmt); err != nil {
			return nil, fmt.Errorf("sqlite: scanning table: %w", err)
		}
		stmt = strings.TrimSpace(stmt)
		t := &schema.Table{
			Name: name,
			Attrs: []schema.Attr{
				&CreateStmt{S: strings.TrimSpace(stmt)},
			},
		}
		if strings.HasSuffix(stmt, "WITHOUT ROWID") || strings.HasSuffix(stmt, "without rowid") {
			t.Attrs = append(t.Attrs, &WithoutRowID{})
		}
		tables = append(tables, t)
	}
	return tables, nil
}

// schemas returns the list of the schemas in the database.
func (i *inspect) databases(ctx context.Context, opts *schema.InspectRealmOption) ([]*schema.Schema, error) {
	var (
		args  []interface{}
		query = databasesQuery
	)
	if opts != nil && len(opts.Schemas) > 0 {
		query += " WHERE name IN (" + strings.Repeat("?, ", len(opts.Schemas)-1) + "?)"
		for _, s := range opts.Schemas {
			args = append(args, s)
		}
	}
	rows, err := i.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: querying schemas: %w", err)
	}
	defer rows.Close()
	var schemas []*schema.Schema
	for rows.Next() {
		var name, file sql.NullString
		if err := rows.Scan(&name, &file); err != nil {
			return nil, err
		}
		// File is missing if the database is not
		// associated with a file (:memory: mode).
		if file.String == "" {
			file.String = ":memory:"
		}
		schemas = append(schemas, &schema.Schema{
			Name:  name.String,
			Attrs: []schema.Attr{&File{Name: file.String}},
		})
	}
	return schemas, nil
}

type (
	// File describes a database file.
	File struct {
		schema.Attr
		Name string
	}

	// CreateStmt describes the SQL statement used to create a resource.
	CreateStmt struct {
		schema.Attr
		S string
	}

	// AutoIncrement describes the `AUTOINCREMENT` configuration.
	// https://www.sqlite.org/autoinc.html
	AutoIncrement struct {
		schema.Attr
		// Seq represents the value in sqlite_sequence table.
		// i.e. https://www.sqlite.org/fileformat2.html#seqtab.
		//
		// Setting this value manually to > 0 indicates that
		// a custom value is necessary and should be handled
		// on migrate.
		Seq int64
	}

	// WithoutRowID describes the `WITHOUT ROWID` configuration.
	// See: https://sqlite.org/withoutrowid.html
	WithoutRowID struct {
		schema.Attr
	}

	// IndexPredicate describes a partial index predicate.
	// See: https://www.sqlite.org/partialindex.html
	IndexPredicate struct {
		schema.Attr
		P string
	}

	// IndexOrigin describes how the index was created.
	// See: https://www.sqlite.org/pragma.html#pragma_index_list
	IndexOrigin struct {
		schema.Attr
		O string
	}

	// A UUIDType defines a UUID type.
	UUIDType struct {
		schema.Type
		T string
	}
)

func columnParts(t string) []string {
	t = strings.TrimSpace(strings.ToLower(t))
	parts := strings.FieldsFunc(t, func(r rune) bool {
		return r == '(' || r == ')' || r == ' ' || r == ','
	})
	for k := 0; k < 2; k++ {
		// Join the type back if it was separated with space (e.g. 'varying character').
		if len(parts) > 1 && !isNumber(parts[0]) && !isNumber(parts[1]) {
			parts[1] = parts[0] + " " + parts[1]
			parts = parts[1:]
		}
	}
	return parts
}

func defaultExpr(x string) schema.Expr {
	switch {
	// Literals definition.
	// https://www.sqlite.org/syntax/literal-value.html
	case sqlx.IsLiteralBool(x), sqlx.IsLiteralNumber(x), sqlx.IsQuoted(x, '"', '\''), isBlob(x):
		return &schema.Literal{V: x}
	default:
		// We wrap the CURRENT_TIMESTAMP literals in raw-expressions
		// as they are not parsable in most decoders.
		return &schema.RawExpr{X: x}
	}
}

// isNumber reports whether the string is a number (category N).
func isNumber(s string) bool {
	for _, r := range s {
		if !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

// blob literals are hex strings preceded by 'x' (or 'X).
func isBlob(s string) bool {
	if (strings.HasPrefix(s, "x'") || strings.HasPrefix(s, "X'")) && strings.HasSuffix(s, "'") {
		_, err := strconv.ParseUint(s[2:len(s)-1], 16, 64)
		return err == nil
	}
	return false
}

var reAutoinc = regexp.MustCompile("(?i)(?:[(,]\\s*)[\"`]?(\\w+)[\"`]?\\s+INTEGER\\s+[^,]*PRIMARY\\s+KEY\\s+[^,]*AUTOINCREMENT")

// autoinc checks if the table contains a "PRIMARY KEY AUTOINCREMENT" on its
// CREATE statement, according to https://www.sqlite.org/syntax/column-constraint.html.
// This is a workaround until we will embed a proper SQLite parser in atlas.
func autoinc(t *schema.Table) error {
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE statement for table: %q", t.Name)
	}
	if t.PrimaryKey == nil || len(t.PrimaryKey.Parts) != 1 || t.PrimaryKey.Parts[0].C == nil {
		return nil
	}
	matches := reAutoinc.FindStringSubmatch(c.S)
	if len(matches) != 2 {
		return nil
	}
	pkc, ok := t.Column(matches[1])
	if !ok {
		return fmt.Errorf("sqlite: column %q was not found for AUTOINCREMENT", matches[1])
	}
	if t.PrimaryKey == nil || len(t.PrimaryKey.Parts) != 1 || t.PrimaryKey.Parts[0].C != pkc {
		return fmt.Errorf("sqlite: unexpected primary key: %v", t.PrimaryKey)
	}
	inc := &AutoIncrement{}
	// Annotate table elements with "AUTOINCREMENT".
	t.PrimaryKey.Attrs = append(t.PrimaryKey.Attrs, inc)
	pkc.Attrs = append(pkc.Attrs, inc)
	return nil
}

// The following regexes extract named FKs and CHECK constraints defined in table-constraints or inlined
// as column-constraints. Note, we assume the SQL statements are valid as they are returned by SQLite.
var (
	reFKC   = regexp.MustCompile("(?i)(?:[(,]\\s*)[\"`]*(\\w+)[\"`]*[^,]*\\s+CONSTRAINT\\s+[\"`]*(\\w+)[\"`]*\\s+REFERENCES\\s+[\"`]*(\\w+)[\"`]*\\s*\\(([,\"` \\w]+)\\)")
	reFKT   = regexp.MustCompile("(?i)CONSTRAINT\\s+[\"`]*(\\w+)[\"`]*\\s+FOREIGN\\s+KEY\\s*\\(([,\"` \\w]+)\\)\\s+REFERENCES\\s+[\"`]*(\\w+)[\"`]*\\s*\\(([,\"` \\w]+)\\)")
	reCheck = regexp.MustCompile("(?i)(?:CONSTRAINT\\s+[\"`]?(\\w+)[\"`]?\\s+)?CHECK\\s*\\(")
)

// fillConstName fills foreign-key constrain names from CREATE TABLE statement.
func fillConstName(t *schema.Table) error {
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE statement for table: %q", t.Name)
	}
	// Loop over table constraints.
	for _, m := range reFKT.FindAllStringSubmatch(c.S, -1) {
		if len(m) != 5 {
			return fmt.Errorf("unexpected number of matches for a table constraint: %q", m)
		}
		// Pattern matches "constraint_name", "columns", "ref_table" and "ref_columns".
		for _, fk := range t.ForeignKeys {
			// Found a foreign-key match for the constraint.
			if matchFK(fk, columns(m[2]), m[3], columns(m[4])) {
				fk.Symbol = m[1]
				break
			}
		}
	}
	// Loop over inlined column constraints.
	for _, m := range reFKC.FindAllStringSubmatch(c.S, -1) {
		if len(m) != 5 {
			return fmt.Errorf("unexpected number of matches for a column constraint: %q", m)
		}
		// Pattern matches "column", "constraint_name", "ref_table" and "ref_columns".
		for _, fk := range t.ForeignKeys {
			// Found a foreign-key match for the constraint.
			if matchFK(fk, columns(m[1]), m[3], columns(m[4])) {
				fk.Symbol = m[2]
				break
			}
		}
	}
	return nil
}

// columns from the matched regex above.
func columns(s string) []string {
	names := strings.Split(s, ",")
	for i := range names {
		names[i] = strings.Trim(strings.TrimSpace(names[i]), "`\"")
	}
	return names
}

// matchFK reports if the foreign-key matches the given attributes.
func matchFK(fk *schema.ForeignKey, columns []string, refTable string, refColumns []string) bool {
	if len(fk.Columns) != len(columns) || fk.RefTable.Name != refTable || len(fk.RefColumns) != len(refColumns) {
		return false
	}
	for i := range columns {
		if fk.Columns[i].Name != columns[i] {
			return false
		}
	}
	for i := range refColumns {
		if fk.RefColumns[i].Name != refColumns[i] {
			return false
		}
	}
	return true
}

// fillChecks extracts the CHECK constrains from the CREATE TABLE statement,
// and appends them to the table attributes.
func fillChecks(t *schema.Table) error {
	var c CreateStmt
	if !sqlx.Has(t.Attrs, &c) {
		return fmt.Errorf("missing CREATE statement for table: %q", t.Name)
	}
	for i := 0; i < len(c.S); {
		idx := reCheck.FindStringSubmatchIndex(c.S[i:])
		// No more matches.
		if len(idx) != 4 {
			break
		}
		var (
			r, l int
			expr = c.S[idx[1]-1:]
		)
		for i := 0; i < len(expr); i++ {
			switch expr[i] {
			case '(':
				r++
			case ')':
				l++
			case '\'', '"':
				// Skip unescaped strings.
				if j := strings.IndexByte(expr[i+1:], expr[i]); j != -1 {
					i += j + 1
				}
			}
			// Balanced parens.
			if r == l {
				check := &schema.Check{Expr: expr[:i+1]}
				// Matching group for constraint name.
				if idx[2] != -1 && idx[3] != -1 {
					check.Name = c.S[idx[2]:idx[3]]
				}
				t.Attrs = append(t.Attrs, check)
				idx[1] = idx[1] + i
				break
			}
		}
		c.S = c.S[idx[1]:]
	}
	return nil
}

const (
	// Name of main database file.
	mainFile = "main"
	// Query to list attached database files.
	databasesQuery = "SELECT `name`, `file` FROM pragma_database_list()"
	// Query to list database tables.
	tablesQuery = "SELECT `name`, `sql` FROM sqlite_master WHERE `type` = 'table' AND `name` NOT LIKE 'sqlite_%'"
	// Query to list table information.
	columnsQuery = "SELECT `name`, `type`, (not `notnull`) AS `nullable`, `dflt_value`, (`pk` <> 0) AS `pk`  FROM pragma_table_info('%s') ORDER BY `pk`, `cid`"
	// Query to list table indexes.
	indexesQuery = "SELECT `il`.`name`, `il`.`unique`, `il`.`origin`, `il`.`partial`, `m`.`sql` FROM pragma_index_list('%s') AS il JOIN sqlite_master AS m ON il.name = m.name"
	// Query to list index columns.
	indexColumnsQuery = "SELECT name, desc FROM pragma_index_xinfo('%s') WHERE key = 1 ORDER BY seqno"
	// Query to list table foreign-keys.
	fksQuery = "SELECT `id`, `from`, `to`, `table`, `on_update`, `on_delete` FROM pragma_foreign_key_list('%s') ORDER BY id, seq"
)
