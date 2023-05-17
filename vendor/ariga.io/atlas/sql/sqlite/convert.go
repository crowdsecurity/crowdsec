// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package sqlite

import (
	"fmt"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/schema"
)

// FormatType converts types to one format. A lowered format.
// This is due to SQLite flexibility to allow any data types
// and use a set of rules to define the type affinity.
// See: https://www.sqlite.org/datatype3.html
func FormatType(t schema.Type) (string, error) {
	var f string
	switch t := t.(type) {
	case *schema.BoolType:
		f = strings.ToLower(t.T)
	case *schema.BinaryType:
		f = strings.ToLower(t.T)
	case *schema.EnumType:
		f = t.T
	case *schema.IntegerType:
		f = strings.ToLower(t.T)
	case *schema.StringType:
		f = strings.ToLower(t.T)
	case *schema.TimeType:
		f = strings.ToLower(t.T)
	case *schema.FloatType:
		f = strings.ToLower(t.T)
	case *schema.DecimalType:
		f = strings.ToLower(t.T)
	case *schema.JSONType:
		f = strings.ToLower(t.T)
	case *schema.SpatialType:
		f = strings.ToLower(t.T)
	case *UUIDType:
		f = strings.ToLower(t.T)
	case *schema.UnsupportedType:
		return "", fmt.Errorf("sqlite: unsupported type: %q", t.T)
	default:
		return "", fmt.Errorf("sqlite: invalid schema type: %T", t)
	}
	return f, nil
}

// ParseType returns the schema.Type value represented by the given raw type.
// It is expected to be one of the types in https://www.sqlite.org/datatypes.html,
// or some of the common types used by ORMs like Ent.
func ParseType(c string) (schema.Type, error) {
	// A datatype may be zero or more names.
	if c == "" {
		return &schema.UnsupportedType{}, nil
	}
	parts := columnParts(c)
	switch t := parts[0]; t {
	case "bool", "boolean":
		return &schema.BoolType{T: t}, nil
	case "blob":
		return &schema.BinaryType{T: t}, nil
	case "int2", "int8", "int", "integer", "tinyint", "smallint", "mediumint", "bigint", "unsigned big int":
		// All integer types have the same "type affinity".
		return &schema.IntegerType{T: t}, nil
	case "real", "double", "double precision", "float":
		return &schema.FloatType{T: t}, nil
	case "numeric", "decimal":
		ct := &schema.DecimalType{T: t}
		if len(parts) > 1 {
			p, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse precision %q", parts[1])
			}
			ct.Precision = int(p)
		}
		if len(parts) > 2 {
			s, err := strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse scale %q", parts[1])
			}
			ct.Scale = int(s)
		}
		return ct, nil
	case "char", "character", "varchar", "varying character", "nchar", "native character", "nvarchar", "text", "clob":
		ct := &schema.StringType{T: t}
		if len(parts) > 1 {
			p, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse size %q", parts[1])
			}
			ct.Size = int(p)
		}
		return ct, nil
	case "json":
		return &schema.JSONType{T: t}, nil
	case "date", "datetime", "time", "timestamp":
		return &schema.TimeType{T: t}, nil
	case "uuid":
		return &UUIDType{T: t}, nil
	default:
		return &schema.UnsupportedType{T: t}, nil
	}
}
