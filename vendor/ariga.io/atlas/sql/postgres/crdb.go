// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlclient"
)

func init() {
	sqlclient.Register(
		"cockroach",
		sqlclient.DriverOpener(Open),
		sqlclient.RegisterCodec(MarshalHCL, EvalHCL),
		sqlclient.RegisterFlavours("crdb"),
		sqlclient.RegisterURLParser(parser{}),
	)
}

// crdbDiff implements the sqlx.DiffDriver for CockroachDB.
type (
	crdbDiff    struct{ diff }
	crdbInspect struct{ inspect }
)

var _ sqlx.DiffDriver = (*crdbDiff)(nil)

// pathSchema fixes: https://github.com/cockroachdb/cockroach/issues/82040.
func (i *crdbInspect) patchSchema(s *schema.Schema) {
	for _, t := range s.Tables {
		for _, c := range t.Columns {
			id, ok := identity(c.Attrs)
			if !ok {
				continue
			}
			c.Default = nil
			if g := strings.ToUpper(id.Generation); strings.Contains(g, "ALWAYS") {
				id.Generation = "ALWAYS"
			} else if strings.Contains(g, "BY DEFAULT") {
				id.Generation = "BY DEFAULT"
			}
			schema.ReplaceOrAppend(&c.Attrs, id)
		}
	}
}

func (i *crdbInspect) InspectSchema(ctx context.Context, name string, opts *schema.InspectOptions) (*schema.Schema, error) {
	s, err := i.inspect.InspectSchema(ctx, name, opts)
	if err != nil {
		return nil, err
	}
	i.patchSchema(s)
	return s, err
}

func (i *crdbInspect) InspectRealm(ctx context.Context, opts *schema.InspectRealmOption) (*schema.Realm, error) {
	r, err := i.inspect.InspectRealm(ctx, opts)
	if err != nil {
		return nil, err
	}
	for _, s := range r.Schemas {
		i.patchSchema(s)
	}
	return r, nil
}

// Normalize implements the sqlx.Normalizer.
func (cd *crdbDiff) Normalize(from, to *schema.Table) error {
	cd.normalize(from)
	cd.normalize(to)
	return nil
}

func (cd *crdbDiff) ColumnChange(fromT *schema.Table, from, to *schema.Column) (schema.ChangeKind, error) {
	// All serial types in Cockroach are implemented as bigint.
	// See: https://www.cockroachlabs.com/docs/stable/serial.html#generated-values-for-mode-sql_sequence-and-sql_sequence_cached.
	for _, c := range []*schema.Column{from, to} {
		if _, ok := c.Type.Type.(*SerialType); ok {
			c.Type.Type = &schema.IntegerType{
				T: TypeBigInt,
			}
			to.Default = nil
			from.Default = nil
		}
	}
	return cd.diff.ColumnChange(fromT, from, to)
}

func (cd *crdbDiff) normalize(table *schema.Table) {
	if table.PrimaryKey == nil {
		prim, ok := table.Column("rowid")
		if !ok {
			prim = schema.NewColumn("rowid").
				AddAttrs(Identity{}).
				SetType(&schema.IntegerType{T: TypeBigInt}).
				SetDefault(&schema.RawExpr{X: "unique_rowid()"})
			table.AddColumns(prim)
		}
		table.PrimaryKey = &schema.Index{
			Name:   "primary",
			Unique: true,
			Table:  table,
			Parts: []*schema.IndexPart{{
				SeqNo: 1,
				C:     prim,
			}},
		}
	}
	for _, c := range table.Columns {
		if _, ok := identity(c.Attrs); ok {
			if c.Default != nil {
				c.Default = nil
				continue
			}
		}
		switch t := c.Type.Type.(type) {
		// Integer types are aliased.
		// see: cockroachlabs.com/docs/v21.2/int.html#names-and-aliases.
		case *schema.IntegerType:
			switch t.T {
			case TypeBigInt, TypeInteger, TypeInt8, TypeInt64, TypeInt:
				t.T = TypeBigInt
			case TypeInt2, TypeSmallInt:
				t.T = TypeSmallInt
			}
		case *schema.JSONType:
			switch t.T {
			// Type json is aliased to jsonb.
			case TypeJSON:
				t.T = TypeJSONB
			}
		case *SerialType:
			c.Default = &schema.RawExpr{
				X: "unique_rowid()",
			}
		case *schema.TimeType:
			// "timestamp" and "timestamptz" are accepted as
			// abbreviations for timestamp with(out) time zone.
			switch t.T {
			case "timestamp with time zone":
				t.T = "timestamptz"
			case "timestamp without time zone":
				t.T = "timestamp"
			}
		case *schema.FloatType:
			// The same numeric precision is used in all platform.
			// See: https://www.postgresql.org/docs/current/datatype-numeric.html
			switch {
			case t.T == "float" && t.Precision < 25:
				// float(1) to float(24) are selected as "real" type.
				t.T = "real"
				fallthrough
			case t.T == "real":
				t.Precision = 24
			case t.T == "float" && t.Precision >= 25:
				// float(25) to float(53) are selected as "double precision" type.
				t.T = "double precision"
				fallthrough
			case t.T == "double precision":
				t.Precision = 53
			}
		case *schema.StringType:
			switch t.T {
			case "character", "char":
				// Character without length specifier
				// is equivalent to character(1).
				t.Size = 1
			}
		case *enumType:
			c.Type.Type = &schema.EnumType{T: t.T, Values: t.Values}
		}
	}
}

func (i *inspect) crdbIndexes(ctx context.Context, s *schema.Schema) error {
	rows, err := i.querySchema(ctx, crdbIndexesQuery, s)
	if err != nil {
		return fmt.Errorf("postgres: querying schema %q indexes: %w", s.Name, err)
	}
	defer rows.Close()
	if err := i.crdbAddIndexes(s, rows); err != nil {
		return err
	}
	return rows.Err()
}

var reIndexType = regexp.MustCompile("(?i)USING (BTREE|GIN|GIST)")

func (i *inspect) crdbAddIndexes(s *schema.Schema, rows *sql.Rows) error {
	// Unlike Postgres, Cockroach may have duplicate index names.
	names := make(map[string]*schema.Index)
	for rows.Next() {
		var (
			uniq, primary                        bool
			table, name, createStmt              string
			column, contype, pred, expr, comment sql.NullString
		)
		if err := rows.Scan(&table, &name, &column, &primary, &uniq, &contype, &createStmt, &pred, &expr, &comment); err != nil {
			return fmt.Errorf("cockroach: scanning indexes for schema %q: %w", s.Name, err)
		}
		t, ok := s.Table(table)
		if !ok {
			return fmt.Errorf("table %q was not found in schema", table)
		}
		uniqueName := fmt.Sprintf("%s.%s", table, name)
		idx, ok := names[uniqueName]
		if !ok {
			idx = &schema.Index{
				Name:   name,
				Unique: uniq,
				Table:  t,
			}
			// Extract index type information from index create statement.
			// See: https://www.cockroachlabs.com/docs/stable/create-index.html.
			if parts := reIndexType.FindStringSubmatch(createStmt); len(parts) > 0 {
				idx.Attrs = append(idx.Attrs, &IndexType{T: parts[1]})
			}
			if sqlx.ValidString(comment) {
				idx.Attrs = append(idx.Attrs, &schema.Comment{Text: comment.String})
			}
			if sqlx.ValidString(contype) {
				idx.Attrs = append(idx.Attrs, &ConType{T: contype.String})
			}
			if sqlx.ValidString(pred) {
				idx.Attrs = append(idx.Attrs, &IndexPredicate{P: pred.String})
			}
			names[uniqueName] = idx
			if primary {
				t.PrimaryKey = idx
			} else {
				t.Indexes = append(t.Indexes, idx)
			}
		}
		part := &schema.IndexPart{SeqNo: len(idx.Parts) + 1, Desc: strings.Contains(createStmt, "DESC")}
		switch {
		case sqlx.ValidString(column):
			part.C, ok = t.Column(column.String)
			if !ok {
				return fmt.Errorf("cockroach: column %q was not found for index %q", column.String, idx.Name)
			}
			part.C.Indexes = append(part.C.Indexes, idx)
		case sqlx.ValidString(expr):
			part.X = &schema.RawExpr{
				X: expr.String,
			}
		default:
			return fmt.Errorf("cockroach: invalid part for index %q", idx.Name)
		}
		idx.Parts = append(idx.Parts, part)
	}
	return nil
}

// CockroachDB types that are not part of PostgreSQL.
const (
	TypeInt64    = "int64"
	TypeGeometry = "geometry"
)

// CockroachDB query for getting schema indexes.
const crdbIndexesQuery = `
SELECT
	t.relname AS table_name,
	i.relname AS index_name,
	a.attname AS column_name,
	idx.indisprimary AS primary,
	idx.indisunique AS unique,
	c.contype AS constraint_type,
	pgi.indexdef create_stmt,
	pg_get_expr(idx.indpred, idx.indrelid) AS predicate,
	pg_get_indexdef(idx.indexrelid, idx.ord, false) AS expression,
	pg_catalog.obj_description(i.oid, 'pg_class') AS comment
	FROM
	(
		select
			*,
			generate_series(1,array_length(i.indkey,1)) as ord,
			unnest(i.indkey) AS key
		from pg_index i
	) idx
	JOIN pg_class i ON i.oid = idx.indexrelid
	JOIN pg_class t ON t.oid = idx.indrelid
	JOIN pg_namespace n ON n.oid = t.relnamespace
	LEFT JOIN pg_constraint c ON idx.indexrelid = c.conindid
	LEFT JOIN pg_indexes pgi ON pgi.tablename = t.relname AND indexname = i.relname AND n.nspname = pgi.schemaname
	LEFT JOIN pg_attribute a ON (a.attrelid, a.attnum) = (idx.indrelid, idx.key)
WHERE
	n.nspname = $1
	AND t.relname IN (%s)
	AND COALESCE(c.contype, '') <> 'f'
ORDER BY
	table_name, index_name, idx.ord
`

const crdbColumnsQuery = `
SELECT
	t1.table_name,
	t1.column_name,
	t1.data_type,
	pg_catalog.format_type(a.atttypid, a.atttypmod) AS format_type,
	t1.is_nullable,
	t1.column_default,
	t1.character_maximum_length,
	t1.numeric_precision,
	t1.datetime_precision,
	t1.numeric_scale,
	t1.interval_type,
	t1.character_set_name,
	t1.collation_name,
	t1.is_identity,
	t5.start_value as identity_start,
	t5.increment_by as identity_increment,
	t5.last_value AS identity_last,
	t1.identity_generation,
	t1.generation_expression,
	col_description(t3.oid, "ordinal_position") AS comment,
	t4.typtype,
	t4.typelem,
	(CASE WHEN t4.typcategory = 'A' AND t4.typelem <> 0 THEN (SELECT t.typtype FROM pg_catalog.pg_type t WHERE t.oid = t4.typelem) END) AS elemtyp,
	t4.oid
FROM
	"information_schema"."columns" AS t1
	JOIN pg_catalog.pg_namespace AS t2 ON t2.nspname = t1.table_schema
	JOIN pg_catalog.pg_class AS t3 ON t3.relnamespace = t2.oid AND t3.relname = t1.table_name
	JOIN pg_catalog.pg_attribute AS a ON a.attrelid = t3.oid AND a.attname = t1.column_name
	LEFT JOIN pg_catalog.pg_type AS t4
	ON t1.udt_name = t4.typname
	LEFT JOIN pg_sequences AS t5
	ON quote_ident(t5.schemaname) || '.' || quote_ident(t5.sequencename) = btrim(btrim(t1.column_default, 'nextval('''), '''::REGCLASS)')
WHERE
	t1.table_schema = $1 AND t1.table_name IN (%s)
ORDER BY
	t1.table_name, t1.ordinal_position
`
