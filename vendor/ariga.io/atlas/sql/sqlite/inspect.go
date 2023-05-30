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

// A diff provides an SQLite implementation for schema.Inspector.
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
	if opts == nil {
		opts = &schema.InspectRealmOption{}
	}
	r := schema.NewRealm(schemas...)
	if !sqlx.ModeInspectRealm(opts).Is(schema.InspectTables) {
		return sqlx.ExcludeRealm(r, opts.Exclude)
	}
	for _, s := range schemas {
		tables, err := i.tables(ctx, nil)
		if err != nil {
			return nil, err
		}
		s.AddTables(tables...)
		for _, t := range tables {
			if err := i.inspectTable(ctx, t); err != nil {
				return nil, err
			}
		}
	}
	sqlx.LinkSchemaTables(r.Schemas)
	return sqlx.ExcludeRealm(r, opts.Exclude)
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
	if opts == nil {
		opts = &schema.InspectOptions{}
	}
	r := schema.NewRealm(schemas...)
	if !sqlx.ModeInspectSchema(opts).Is(schema.InspectTables) {
		return sqlx.ExcludeSchema(r.Schemas[0], opts.Exclude)
	}
	tables, err := i.tables(ctx, opts)
	if err != nil {
		return nil, err
	}
	r.Schemas[0].AddTables(tables...)
	for _, t := range tables {
		if err := i.inspectTable(ctx, t); err != nil {
			return nil, err
		}
	}
	sqlx.LinkSchemaTables(schemas)
	return sqlx.ExcludeSchema(r.Schemas[0], opts.Exclude)
}

func (i *inspect) inspectTable(ctx context.Context, t *schema.Table) error {
	if err := i.columns(ctx, t); err != nil {
		return err
	}
	if err := i.indexes(ctx, t); err != nil {
		return err
	}
	if err := i.fks(ctx, t); err != nil {
		return err
	}
	if err := fillChecks(t); err != nil {
		return err
	}
	return nil
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
		hidden              sql.NullInt64
		name, typ, defaults sql.NullString
		err                 error
	)
	if err = rows.Scan(&name, &typ, &nullable, &defaults, &primary, &hidden); err != nil {
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
	if defaults.Valid {
		c.Default = defaultExpr(defaults.String)
	}
	// The hidden flag is set to 2 for VIRTUAL columns, and to
	// 3 for STORED columns. See: sqlite/pragma.c#sqlite3Pragma.
	if hidden.Int64 >= 2 {
		if err := setGenExpr(t, c, hidden.Int64); err != nil {
			return err
		}
	}
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

// A regexp to extract index parts.
var reIdxParts = regexp.MustCompile("(?i)ON\\s+[\"`]*(?:\\w+)[\"`]*\\s*\\((.+)\\)")

func (i *inspect) indexInfo(ctx context.Context, t *schema.Table, idx *schema.Index) error {
	var (
		hasExpr   bool
		rows, err = i.QueryContext(ctx, fmt.Sprintf(indexColumnsQuery, idx.Name))
	)
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
			hasExpr = true
			part.X = &schema.RawExpr{X: "<unsupported>"}
		default:
			return fmt.Errorf("sqlite: column %q was not found for index %q", name.String, idx.Name)
		}
		idx.Parts = append(idx.Parts, part)
	}
	if !hasExpr {
		return nil
	}
	var c CreateStmt
	if !sqlx.Has(idx.Attrs, &c) || !reIdxParts.MatchString(c.S) {
		return nil
	}
	parts := strings.Split(reIdxParts.FindStringSubmatch(c.S)[1], ",")
	// Unable to parse index parts correctly.
	if len(parts) != len(idx.Parts) {
		return nil
	}
	for i, p := range idx.Parts {
		if p.X != nil {
			p.X.(*schema.RawExpr).X = strings.TrimSpace(parts[i])
		}
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
		args  []any
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
		args  []any
		query = databasesQuery
	)
	if opts != nil && len(opts.Schemas) > 0 {
		query = fmt.Sprintf(databasesQueryArgs, strings.Repeat("?, ", len(opts.Schemas)-1)+"?")
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

// setGenExpr extracts the generated expression from the CREATE statement
// and appends it to the column.
func setGenExpr(t *schema.Table, c *schema.Column, f int64) error {
	var s CreateStmt
	if !sqlx.Has(t.Attrs, &s) {
		return fmt.Errorf("missing CREATE statement for table: %q", t.Name)
	}
	re, err := regexp.Compile(fmt.Sprintf("(?:[(,]\\s*)[\"`]*(%s)[\"`]*[^,]*(?i:GENERATED\\s+ALWAYS)*\\s*(?i:AS){1}\\s*\\(", c.Name))
	if err != nil {
		return err
	}
	idx := re.FindAllStringIndex(s.S, 1)
	if len(idx) != 1 || len(idx[0]) != 2 {
		return fmt.Errorf("sqlite: generation expression for column %q was not found in create statement", c.Name)
	}
	expr := scanExpr(s.S[idx[0][1]-1:])
	if expr == "" {
		return fmt.Errorf("sqlite: unexpected empty generation expression for column %q", c.Name)
	}
	typ := virtual
	if f == 3 {
		typ = stored
	}
	c.SetGeneratedExpr(&schema.GeneratedExpr{Expr: expr, Type: typ})
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
		check := &schema.Check{Expr: scanExpr(c.S[idx[1]-1:])}
		// Matching group for constraint name.
		if idx[2] != -1 && idx[3] != -1 {
			check.Name = c.S[idx[2]:idx[3]]
		}
		t.Attrs = append(t.Attrs, check)
		c.S = c.S[idx[1]+len(check.Expr)-1:]
	}
	return nil
}

// scanExpr scans the expression string (wrapped with parens)
// until its end in the given string. e.g. "(a+1), c int ...".
func scanExpr(expr string) string {
	var r, l int
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
			return expr[:i+1]
		}
	}
	return ""
}

const (
	// Name of main database file.
	mainFile = "main"
	// Query to list attached database files.
	databasesQuery     = "SELECT `name`, `file` FROM pragma_database_list() WHERE `name` <> 'temp'"
	databasesQueryArgs = "SELECT `name`, `file` FROM pragma_database_list() WHERE `name` IN (%s)"
	// Query to list database tables.
	tablesQuery = "SELECT `name`, `sql` FROM sqlite_master WHERE `type` = 'table' AND `name` NOT LIKE 'sqlite_%'"
	// Query to list table information.
	columnsQuery = "SELECT `name`, `type`, (not `notnull`) AS `nullable`, `dflt_value`, (`pk` <> 0) AS `pk`, `hidden` FROM pragma_table_xinfo('%s') ORDER BY `pk`, `cid`"
	// Query to list table indexes.
	indexesQuery = "SELECT `il`.`name`, `il`.`unique`, `il`.`origin`, `il`.`partial`, `m`.`sql` FROM pragma_index_list('%s') AS il JOIN sqlite_master AS m ON il.name = m.name"
	// Query to list index columns.
	indexColumnsQuery = "SELECT name, desc FROM pragma_index_xinfo('%s') WHERE key = 1 ORDER BY seqno"
	// Query to list table foreign-keys.
	fksQuery = "SELECT `id`, `from`, `to`, `table`, `on_update`, `on_delete` FROM pragma_foreign_key_list('%s') ORDER BY id, seq"
)
