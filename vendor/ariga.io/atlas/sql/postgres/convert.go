// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package postgres

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ariga.io/atlas/sql/schema"
)

// FormatType converts schema type to its column form in the database.
// An error is returned if the type cannot be recognized.
func FormatType(t schema.Type) (string, error) {
	var f string
	switch t := t.(type) {
	case *ArrayType:
		f = strings.ToLower(t.T)
	case *BitType:
		f = strings.ToLower(t.T)
		// BIT without a length is equivalent to BIT(1).
		if f == TypeBit && t.Len == 0 {
			f = fmt.Sprintf("%s(1)", f)
		}
	case *schema.BoolType:
		f = strings.ToLower(t.T)
	case *schema.BinaryType:
		f = strings.ToLower(t.T)
	case *CurrencyType:
		f = strings.ToLower(t.T)
	case *schema.EnumType:
		if t.T == "" {
			return "", errors.New("postgres: missing enum type name")
		}
		f = t.T
	case *schema.IntegerType:
		switch f = strings.ToLower(t.T); f {
		case TypeSmallInt, TypeInteger, TypeBigInt:
		case TypeInt2:
			f = TypeSmallInt
		case TypeInt, TypeInt4:
			f = TypeInteger
		case TypeInt8:
			f = TypeBigInt
		}
	case *schema.StringType:
		switch f = strings.ToLower(t.T); f {
		case TypeText:
		// CHAR(n) is alias for CHARACTER(n). If not length was
		// specified, the definition is equivalent to CHARACTER(1).
		case TypeChar, TypeCharacter:
			n := t.Size
			if n == 0 {
				n = 1
			}
			f = fmt.Sprintf("%s(%d)", TypeCharacter, n)
		// VARCHAR(n) is alias for CHARACTER VARYING(n). If not length
		// was specified, the type accepts strings of any size.
		case TypeVarChar, TypeCharVar:
			f = TypeCharVar
			if t.Size != 0 {
				f = fmt.Sprintf("%s(%d)", TypeCharVar, t.Size)
			}
		default:
			return "", fmt.Errorf("postgres: unexpected string type: %q", t.T)
		}
	case *schema.TimeType:
		switch f = strings.ToLower(t.T); f {
		// TIMESTAMPTZ is accepted as an abbreviation for TIMESTAMP WITH TIME ZONE.
		case TypeTimestampTZ:
			f = TypeTimestampWTZ
		// TIME be equivalent to TIME WITHOUT TIME ZONE.
		case TypeTime:
			f = TypeTimeWOTZ
		// TIMESTAMP be equivalent to TIMESTAMP WITHOUT TIME ZONE.
		case TypeTimestamp:
			f = TypeTimestampWOTZ
		}
		if t.Precision != defaultTimePrecision && strings.HasPrefix(f, "time") {
			p := strings.Split(f, " ")
			f = fmt.Sprintf("%s(%d)%s", p[0], t.Precision, strings.Join(p[1:], " "))
		}
	case *schema.FloatType:
		switch f = strings.ToLower(t.T); f {
		case TypeFloat4:
			f = TypeReal
		case TypeFloat8:
			f = TypeDouble
		}
	case *schema.DecimalType:
		switch f = strings.ToLower(t.T); f {
		case TypeNumeric:
		// The DECIMAL type is an alias for NUMERIC.
		case TypeDecimal:
			f = TypeNumeric
		default:
			return "", fmt.Errorf("postgres: unexpected decimal type: %q", t.T)
		}
		switch p, s := t.Precision, t.Scale; {
		case p == 0 && s == 0:
		case s < 0:
			return "", fmt.Errorf("postgres: decimal type must have scale >= 0: %d", s)
		case p == 0 && s > 0:
			return "", fmt.Errorf("postgres: decimal type must have precision between 1 and 1000: %d", p)
		case s == 0:
			f = fmt.Sprintf("%s(%d)", f, p)
		default:
			f = fmt.Sprintf("%s(%d,%d)", f, p, s)
		}
	case *SerialType:
		switch f = strings.ToLower(t.T); f {
		case TypeSmallSerial, TypeSerial, TypeBigSerial:
		case TypeSerial2:
			f = TypeSmallSerial
		case TypeSerial4:
			f = TypeSerial
		case TypeSerial8:
			f = TypeBigSerial
		default:
			return "", fmt.Errorf("postgres: unexpected serial type: %q", t.T)
		}
	case *schema.JSONType:
		f = strings.ToLower(t.T)
	case *UUIDType:
		f = strings.ToLower(t.T)
	case *schema.SpatialType:
		f = strings.ToLower(t.T)
	case *NetworkType:
		f = strings.ToLower(t.T)
	case *UserDefinedType:
		f = strings.ToLower(t.T)
	case *schema.UnsupportedType:
		return "", fmt.Errorf("postgres: unsupported type: %q", t.T)
	default:
		return "", fmt.Errorf("postgres: invalid schema type: %T", t)
	}
	return f, nil
}

// mustFormat calls to FormatType and panics in case of error.
func mustFormat(t schema.Type) string {
	s, err := FormatType(t)
	if err != nil {
		panic(err)
	}
	return s
}

// ParseType returns the schema.Type value represented by the given raw type.
// The raw value is expected to follow the format in PostgreSQL information schema
// or as an input for the CREATE TABLE statement.
func ParseType(typ string) (schema.Type, error) {
	d, err := parseColumn(typ)
	if err != nil {
		return nil, err
	}
	// Normalize PostgreSQL array data types from "CREATE TABLE" format to
	// "INFORMATION_SCHEMA" format (i.e. as it is inspected from the database).
	if t, ok := arrayType(typ); ok {
		d = &columnDesc{typ: TypeArray, udt: t}
	}
	t := columnType(d)
	// If the type is unknown (to us), we fallback to user-defined but expect
	// to improve this in future versions by ensuring this against the database.
	if ut, ok := t.(*schema.UnsupportedType); ok {
		t = &UserDefinedType{T: ut.T}
	}
	return t, nil
}

// reArray parses array declaration. See: https://postgresql.org/docs/current/arrays.html.
var reArray = regexp.MustCompile(`(?i)(\w+)\s*(?:(?:\[\d*])+|\s+ARRAY\s*(?:\[\d*])*)`)

// arrayType reports if the given string is an array type (e.g. int[], text[2]),
// and returns its "udt_name" as it was inspected from the database.
func arrayType(t string) (string, bool) {
	matches := reArray.FindStringSubmatch(t)
	if len(matches) != 2 {
		return "", false
	}
	return matches[1], true
}

// columnDesc represents a column descriptor.
type columnDesc struct {
	typ           string
	size          int64
	udt           string
	precision     int64
	timePrecision int64
	scale         int64
	typtype       string
	typid         int64
	parts         []string
}

var reDigits = regexp.MustCompile(`\d`)

func parseColumn(s string) (*columnDesc, error) {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '(' || r == ')' || r == ' ' || r == ','
	})
	var (
		err error
		c   = &columnDesc{
			typ:   parts[0],
			parts: parts,
		}
	)
	switch c.parts[0] {
	case TypeVarChar, TypeCharVar, TypeChar, TypeCharacter:
		if err := parseCharParts(c.parts, c); err != nil {
			return nil, err
		}
	case TypeDecimal, TypeNumeric:
		if len(parts) > 1 {
			c.precision, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("postgres: parse precision %q: %w", parts[1], err)
			}
		}
		if len(parts) > 2 {
			c.scale, err = strconv.ParseInt(parts[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("postgres: parse scale %q: %w", parts[1], err)
			}
		}
	case TypeBit:
		if err := parseBitParts(parts, c); err != nil {
			return nil, err
		}
	case TypeDouble, TypeFloat8:
		c.precision = 53
	case TypeReal, TypeFloat4:
		c.precision = 24
	case TypeTime, TypeTimestamp, TypeTimestampTZ:
		// If the second part is only one digit it is the precision argument.
		// For cases like "timestamp(4) with time zone" make sure to not drop the rest of the type definition.
		offset := 1
		if len(parts) > 1 && reDigits.MatchString(parts[1]) {
			offset = 2
			c.timePrecision, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("postgres: parse time precision %q: %w", parts[1], err)
			}
		}
		// Append time zone part (if present).
		if len(parts) > offset {
			c.typ = fmt.Sprintf("%s %s", c.typ, strings.Join(parts[offset:], " "))
		}
	default:
		c.typ = s
	}
	return c, nil
}

func parseCharParts(parts []string, c *columnDesc) error {
	j := strings.Join(parts, " ")
	switch {
	case strings.HasPrefix(j, TypeVarChar):
		c.typ = TypeVarChar
		parts = parts[1:]
	case strings.HasPrefix(j, TypeCharVar):
		c.typ = TypeCharVar
		parts = parts[2:]
	default:
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return nil
	}
	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("postgres: parse size %q: %w", parts[1], err)
	}
	c.size = size
	return nil
}

func parseBitParts(parts []string, c *columnDesc) error {
	if len(parts) == 1 {
		c.size = 1
		return nil
	}
	parts = parts[1:]
	if parts[0] == "varying" {
		c.typ = TypeBitVar
		parts = parts[1:]
	}
	if len(parts) == 0 {
		return nil
	}
	size, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("postgres: parse size %q: %w", parts[1], err)
	}
	c.size = size
	return nil
}
