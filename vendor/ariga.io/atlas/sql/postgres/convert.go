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
		// BIT without a length is equivalent to BIT(1),
		// BIT VARYING has unlimited length.
		if f == TypeBit && t.Len > 1 || f == TypeBitVar && t.Len > 0 {
			f = fmt.Sprintf("%s(%d)", f, t.Len)
		}
	case *schema.BoolType:
		// BOOLEAN can be abbreviated as BOOL.
		if f = strings.ToLower(t.T); f == TypeBool {
			f = TypeBoolean
		}
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
	case *IntervalType:
		f = strings.ToLower(t.T)
		if t.F != "" {
			f += " " + strings.ToLower(t.F)
		}
		if t.Precision != nil && *t.Precision != defaultTimePrecision {
			f += fmt.Sprintf("(%d)", *t.Precision)
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
		f = timeAlias(t.T)
		if p := t.Precision; p != nil && *p != defaultTimePrecision && strings.HasPrefix(f, "time") {
			f += fmt.Sprintf("(%d)", *p)
		}
	case *schema.FloatType:
		switch f = strings.ToLower(t.T); f {
		case TypeFloat4:
			f = TypeReal
		case TypeFloat8:
			f = TypeDouble
		case TypeFloat:
			switch {
			case t.Precision > 0 && t.Precision <= 24:
				f = TypeReal
			case t.Precision == 0 || (t.Precision > 24 && t.Precision <= 53):
				f = TypeDouble
			default:
				return "", fmt.Errorf("postgres: precision for type float must be between 1 and 53: %d", t.Precision)
			}
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
	case *XMLType:
		f = strings.ToLower(t.T)
	case *schema.UnsupportedType:
		return "", fmt.Errorf("postgres: unsupported type: %q", t.T)
	default:
		return "", fmt.Errorf("postgres: invalid schema type: %T", t)
	}
	return f, nil
}

// ParseType returns the schema.Type value represented by the given raw type.
// The raw value is expected to follow the format in PostgreSQL information schema
// or as an input for the CREATE TABLE statement.
func ParseType(typ string) (schema.Type, error) {
	var (
		err error
		d   *columnDesc
	)
	// Normalize PostgreSQL array data types from "CREATE TABLE" format to
	// "INFORMATION_SCHEMA" format (i.e. as it is inspected from the database).
	if t, ok := arrayType(typ); ok {
		d = &columnDesc{typ: TypeArray, fmtype: t + "[]"}
	} else if d, err = parseColumn(typ); err != nil {
		return nil, err
	}
	t, err := columnType(d)
	if err != nil {
		return nil, err
	}
	// If the type is unknown (to us), we fall back to user-defined but expect
	// to improve this in future versions by ensuring this against the database.
	if ut, ok := t.(*schema.UnsupportedType); ok {
		t = &UserDefinedType{T: ut.T}
	}
	return t, nil
}

func columnType(c *columnDesc) (schema.Type, error) {
	var typ schema.Type
	switch t := c.typ; strings.ToLower(t) {
	case TypeBigInt, TypeInt8, TypeInt, TypeInteger, TypeInt4, TypeSmallInt, TypeInt2, TypeInt64:
		typ = &schema.IntegerType{T: t}
	case TypeBit, TypeBitVar:
		typ = &BitType{T: t, Len: c.size}
	case TypeBool, TypeBoolean:
		typ = &schema.BoolType{T: t}
	case TypeBytea:
		typ = &schema.BinaryType{T: t}
	case TypeCharacter, TypeChar, TypeCharVar, TypeVarChar, TypeText:
		// A `character` column without length specifier is equivalent to `character(1)`,
		// but `varchar` without length accepts strings of any size (same as `text`).
		typ = &schema.StringType{T: t, Size: int(c.size)}
	case TypeCIDR, TypeInet, TypeMACAddr, TypeMACAddr8:
		typ = &NetworkType{T: t}
	case TypeCircle, TypeLine, TypeLseg, TypeBox, TypePath, TypePolygon, TypePoint, TypeGeometry:
		typ = &schema.SpatialType{T: t}
	case TypeDate:
		typ = &schema.TimeType{T: t}
	case TypeTime, TypeTimeWOTZ, TypeTimeTZ, TypeTimeWTZ, TypeTimestamp,
		TypeTimestampTZ, TypeTimestampWTZ, TypeTimestampWOTZ:
		p := defaultTimePrecision
		if c.timePrecision != nil {
			p = int(*c.timePrecision)
		}
		typ = &schema.TimeType{T: t, Precision: &p}
	case TypeInterval:
		p := defaultTimePrecision
		if c.timePrecision != nil {
			p = int(*c.timePrecision)
		}
		typ = &IntervalType{T: t, Precision: &p}
		if c.interval != "" {
			f, ok := intervalField(c.interval)
			if !ok {
				return &schema.UnsupportedType{T: c.interval}, nil
			}
			typ.(*IntervalType).F = f
		}
	case TypeReal, TypeDouble, TypeFloat, TypeFloat4, TypeFloat8:
		typ = &schema.FloatType{T: t, Precision: int(c.precision)}
	case TypeJSON, TypeJSONB:
		typ = &schema.JSONType{T: t}
	case TypeMoney:
		typ = &CurrencyType{T: t}
	case TypeDecimal, TypeNumeric:
		typ = &schema.DecimalType{T: t, Precision: int(c.precision), Scale: int(c.scale)}
	case TypeSmallSerial, TypeSerial, TypeBigSerial, TypeSerial2, TypeSerial4, TypeSerial8:
		typ = &SerialType{T: t, Precision: int(c.precision)}
	case TypeUUID:
		typ = &UUIDType{T: t}
	case TypeXML:
		typ = &XMLType{T: t}
	case TypeArray:
		// Ignore multi-dimensions or size constraints
		// as they are ignored by the database.
		typ = &ArrayType{T: c.fmtype}
		if t, ok := arrayType(c.fmtype); ok {
			tt, err := ParseType(t)
			if err != nil {
				return nil, err
			}
			if c.elemtyp == "e" {
				// Override the element type in
				// case it is an enum.
				tt = newEnumType(t, c.typelem)
			}
			typ.(*ArrayType).Type = tt
		}
	case TypeUserDefined:
		typ = &UserDefinedType{T: c.fmtype}
		// The `typtype` column is set to 'e' for enum types, and the
		// values are filled in batch after the rows above is closed.
		// https://postgresql.org/docs/current/catalog-pg-type.html
		if c.typtype == "e" {
			typ = newEnumType(c.fmtype, c.typid)
		}
	default:
		typ = &schema.UnsupportedType{T: t}
	}
	return typ, nil
}

// reArray parses array declaration. See: https://postgresql.org/docs/current/arrays.html.
var reArray = regexp.MustCompile(`(?i)(.+?)(( +ARRAY( *\[[ \d]*] *)*)+|( *\[[ \d]*] *)+)$`)

// arrayType reports if the given string is an array type (e.g. int[], text[2]),
// and returns its "udt_name" as it was inspected from the database.
func arrayType(t string) (string, bool) {
	matches := reArray.FindStringSubmatch(t)
	if len(matches) < 2 {
		return "", false
	}
	return strings.TrimSpace(matches[1]), true
}

// reInterval parses declaration of interval fields. See: https://www.postgresql.org/docs/current/datatype-datetime.html.
var reInterval = regexp.MustCompile(`(?i)(?:INTERVAL\s*)?(YEAR|MONTH|DAY|HOUR|MINUTE|SECOND|YEAR TO MONTH|DAY TO HOUR|DAY TO MINUTE|DAY TO SECOND|HOUR TO MINUTE|HOUR TO SECOND|MINUTE TO SECOND)?\s*(?:\(([0-6])\))?$`)

// intervalField reports if the given string is an interval
// field type and returns its value (e.g. SECOND, MINUTE TO SECOND).
func intervalField(t string) (string, bool) {
	matches := reInterval.FindStringSubmatch(t)
	if len(matches) != 3 || matches[1] == "" {
		return "", false
	}
	return matches[1], true
}

// columnDesc represents a column descriptor.
type columnDesc struct {
	typ           string // data_type
	fmtype        string // pg_catalog.format_type
	size          int64  // character_maximum_length
	typtype       string // pg_type.typtype
	typelem       int64  // pg_type.typelem
	elemtyp       string // pg_type.typtype of the array element type above.
	typid         int64  // pg_type.oid
	precision     int64
	timePrecision *int64
	scale         int64
	parts         []string
	interval      string
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
	case TypeDecimal, TypeNumeric, TypeFloat:
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
	case TypeTime, TypeTimeTZ, TypeTimestamp, TypeTimestampTZ:
		t, p := s, int64(defaultTimePrecision)
		// If the second part is only one digit it is the precision argument.
		// For cases like "timestamp(4) with time zone" make sure to not drop
		// the rest of the type definition.
		if len(parts) > 1 && reDigits.MatchString(parts[1]) {
			i, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("postgres: parse time precision %q: %w", parts[1], err)
			}
			p = i
			t = strings.Join(append(c.parts[:1], c.parts[2:]...), " ")
		}
		c.typ = timeAlias(t)
		c.timePrecision = &p
	case TypeInterval:
		matches := reInterval.FindStringSubmatch(s)
		c.interval = matches[1]
		if matches[2] != "" {
			i, err := strconv.ParseInt(matches[2], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("postgres: parse interval precision %q: %w", parts[1], err)
			}
			c.timePrecision = &i
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
		return fmt.Errorf("postgres: parse size %q: %w", parts[0], err)
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

// timeAlias returns the abbreviation for the given time type.
func timeAlias(t string) string {
	switch t = strings.ToLower(t); t {
	// TIMESTAMPTZ be equivalent to TIMESTAMP WITH TIME ZONE.
	case TypeTimestampWTZ:
		t = TypeTimestampTZ
	// TIMESTAMP be equivalent to TIMESTAMP WITHOUT TIME ZONE.
	case TypeTimestampWOTZ:
		t = TypeTimestamp
	// TIME be equivalent to TIME WITHOUT TIME ZONE.
	case TypeTimeWOTZ:
		t = TypeTime
	// TIMETZ be equivalent to TIME WITH TIME ZONE.
	case TypeTimeWTZ:
		t = TypeTimeTZ
	}
	return t
}
