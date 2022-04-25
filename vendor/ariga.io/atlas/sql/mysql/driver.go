// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package mysql

import (
	"context"
	"fmt"
	"strings"

	"ariga.io/atlas/sql/internal/sqlx"
	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/schema"

	"golang.org/x/mod/semver"
)

type (
	// Driver represents a MySQL driver for introspecting database schemas,
	// generating diff between schema elements and apply migrations changes.
	Driver struct {
		conn
		schema.Differ
		schema.Inspector
		migrate.PlanApplier
	}

	// database connection and its information.
	conn struct {
		schema.ExecQuerier
		// System variables that are set on `Open`.
		version string
		collate string
		charset string
	}
)

// Open opens a new MySQL driver.
func Open(db schema.ExecQuerier) (*Driver, error) {
	c := conn{ExecQuerier: db}
	rows, err := db.QueryContext(context.Background(), variablesQuery)
	if err != nil {
		return nil, fmt.Errorf("mysql: query system variables: %w", err)
	}
	if err := sqlx.ScanOne(rows, &c.version, &c.collate, &c.charset); err != nil {
		return nil, fmt.Errorf("mysql: scan system variables: %w", err)
	}
	if c.tidb() {
		return &Driver{
			conn:        c,
			Differ:      &sqlx.Diff{DiffDriver: &tdiff{diff{c}}},
			Inspector:   &tinspect{inspect{c}},
			PlanApplier: &tplanApply{planApply{c}},
		}, nil
	}
	return &Driver{
		conn:        c,
		Differ:      &sqlx.Diff{DiffDriver: &diff{c}},
		Inspector:   &inspect{c},
		PlanApplier: &planApply{c},
	}, nil
}

func (d *Driver) dev() *sqlx.DevDriver {
	return &sqlx.DevDriver{Driver: d, MaxNameLen: 64}
}

// NormalizeRealm returns the normal representation of the given database.
func (d *Driver) NormalizeRealm(ctx context.Context, r *schema.Realm) (*schema.Realm, error) {
	return d.dev().NormalizeRealm(ctx, r)
}

// NormalizeSchema returns the normal representation of the given database.
func (d *Driver) NormalizeSchema(ctx context.Context, s *schema.Schema) (*schema.Schema, error) {
	return d.dev().NormalizeSchema(ctx, s)
}

// supportsCheck reports if the connected database supports
// the CHECK clause, and return the querying for getting them.
func (d *conn) supportsCheck() (string, bool) {
	v, q := "8.0.16", myChecksQuery
	if d.mariadb() {
		v, q = "10.2.1", marChecksQuery
	}
	return q, d.gteV(v)
}

// supportsIndexExpr reports if the connected database supports
// index expressions (functional key part).
func (d *conn) supportsIndexExpr() bool {
	return !d.mariadb() && d.gteV("8.0.13")
}

// supportsDisplayWidth reports if the connected database supports
// getting the display width information from the information schema.
func (d *conn) supportsDisplayWidth() bool {
	// MySQL v8.0.19 dropped the display width
	// information from the information schema
	return d.mariadb() || d.ltV("8.0.19")
}

// supportsExprDefault reports if the connected database supports
// expressions in the DEFAULT clause on column definition.
func (d *conn) supportsExprDefault() bool {
	v := "8.0.13"
	if d.mariadb() {
		v = "10.2.1"
	}
	return d.gteV(v)
}

// supportsEnforceCheck reports if the connected database supports
// the ENFORCED option in CHECK constraint syntax.
func (d *conn) supportsEnforceCheck() bool {
	return !d.mariadb() && d.gteV("8.0.16")
}

// mariadb reports if the Driver is connected to a MariaDB database.
func (d *conn) mariadb() bool {
	return strings.Index(d.version, "MariaDB") > 0
}

// tidb reports if the Driver is connected to a TiDB database.
func (d *conn) tidb() bool {
	return strings.Index(d.version, "TiDB") > 0
}

// compareV returns an integer comparing two versions according to
// semantic version precedence.
func (d *conn) compareV(w string) int {
	v := d.version
	if d.mariadb() {
		v = v[:strings.Index(v, "MariaDB")-1]
	}
	return semver.Compare("v"+v, "v"+w)
}

// gteV reports if the connection version is >= w.
func (d *conn) gteV(w string) bool { return d.compareV(w) >= 0 }

// ltV reports if the connection version is < w.
func (d *conn) ltV(w string) bool { return d.compareV(w) == -1 }

// unescape strings with backslashes returned
// for SQL expressions from information schema.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c != '\\' || i == len(s)-1:
			b.WriteByte(c)
		case s[i+1] == '\'', s[i+1] == '\\':
			b.WriteByte(s[i+1])
			i++
		}
	}
	return b.String()
}

// MySQL standard column types as defined in its codebase. Name and order
// is organized differently than MySQL.
//
// https://github.com/mysql/mysql-server/blob/8.0/include/field_types.h
// https://github.com/mysql/mysql-server/blob/8.0/sql/dd/types/column.h
// https://github.com/mysql/mysql-server/blob/8.0/sql/sql_show.cc
// https://github.com/mysql/mysql-server/blob/8.0/sql/gis/geometries.cc
// https://dev.mysql.com/doc/refman/8.0/en/other-vendor-data-types.html
const (
	TypeBool    = "bool"
	TypeBoolean = "boolean"

	TypeBit       = "bit"       // MYSQL_TYPE_BIT
	TypeInt       = "int"       // MYSQL_TYPE_LONG
	TypeTinyInt   = "tinyint"   // MYSQL_TYPE_TINY
	TypeSmallInt  = "smallint"  // MYSQL_TYPE_SHORT
	TypeMediumInt = "mediumint" // MYSQL_TYPE_INT24
	TypeBigInt    = "bigint"    // MYSQL_TYPE_LONGLONG

	TypeDecimal = "decimal" // MYSQL_TYPE_DECIMAL
	TypeNumeric = "numeric" // MYSQL_TYPE_DECIMAL (numeric_type rule in sql_yacc.yy)
	TypeFloat   = "float"   // MYSQL_TYPE_FLOAT
	TypeDouble  = "double"  // MYSQL_TYPE_DOUBLE
	TypeReal    = "real"    // MYSQL_TYPE_FLOAT or MYSQL_TYPE_DOUBLE (real_type in sql_yacc.yy)

	TypeTimestamp = "timestamp" // MYSQL_TYPE_TIMESTAMP
	TypeDate      = "date"      // MYSQL_TYPE_DATE
	TypeTime      = "time"      // MYSQL_TYPE_TIME
	TypeDateTime  = "datetime"  // MYSQL_TYPE_DATETIME
	TypeYear      = "year"      // MYSQL_TYPE_YEAR

	TypeVarchar    = "varchar"    // MYSQL_TYPE_VAR_STRING, MYSQL_TYPE_VARCHAR
	TypeChar       = "char"       // MYSQL_TYPE_STRING
	TypeVarBinary  = "varbinary"  // MYSQL_TYPE_VAR_STRING + NULL CHARACTER_SET.
	TypeBinary     = "binary"     // MYSQL_TYPE_STRING + NULL CHARACTER_SET.
	TypeBlob       = "blob"       // MYSQL_TYPE_BLOB
	TypeTinyBlob   = "tinyblob"   // MYSQL_TYPE_TINYBLOB
	TypeMediumBlob = "mediumblob" // MYSQL_TYPE_MEDIUM_BLOB
	TypeLongBlob   = "longblob"   // MYSQL_TYPE_LONG_BLOB
	TypeText       = "text"       // MYSQL_TYPE_BLOB + CHARACTER_SET utf8mb4
	TypeTinyText   = "tinytext"   // MYSQL_TYPE_TINYBLOB + CHARACTER_SET utf8mb4
	TypeMediumText = "mediumtext" // MYSQL_TYPE_MEDIUM_BLOB + CHARACTER_SET utf8mb4
	TypeLongText   = "longtext"   // MYSQL_TYPE_LONG_BLOB with + CHARACTER_SET utf8mb4

	TypeEnum = "enum" // MYSQL_TYPE_ENUM
	TypeSet  = "set"  // MYSQL_TYPE_SET
	TypeJSON = "json" // MYSQL_TYPE_JSON

	TypeGeometry           = "geometry"           // MYSQL_TYPE_GEOMETRY
	TypePoint              = "point"              // Geometry_type::kPoint
	TypeMultiPoint         = "multipoint"         // Geometry_type::kMultipoint
	TypeLineString         = "linestring"         // Geometry_type::kLinestring
	TypeMultiLineString    = "multilinestring"    // Geometry_type::kMultilinestring
	TypePolygon            = "polygon"            // Geometry_type::kPolygon
	TypeMultiPolygon       = "multipolygon"       // Geometry_type::kMultipolygon
	TypeGeoCollection      = "geomcollection"     // Geometry_type::kGeometrycollection
	TypeGeometryCollection = "geometrycollection" // Geometry_type::kGeometrycollection
)

// Additional common constants in MySQL.
const (
	IndexTypeBTree    = "BTREE"
	IndexTypeHash     = "HASH"
	IndexTypeFullText = "FULLTEXT"
	IndexTypeSpatial  = "SPATIAL"

	currentTS     = "current_timestamp"
	defaultGen    = "default_generated"
	autoIncrement = "auto_increment"
)
