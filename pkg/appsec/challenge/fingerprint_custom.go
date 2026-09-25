// fingerprint_custom.go holds the `custom` map that hub-distributed detection
// scripts fill in after fpscanner has run, so new detections and false-positive
// fixes can ship without a release.

package challenge

import (
	"encoding/json"
)

// CustomKind tags which field of a CustomValue carries the value.
type CustomKind string

const (
	CustomKindNone    CustomKind = ""
	CustomKindBool    CustomKind = "bool"
	CustomKindString  CustomKind = "string"
	CustomKindNumber  CustomKind = "number"
	CustomKindStrings CustomKind = "strings"
	CustomKindFloats  CustomKind = "floats"
)

// CustomValue is one entry a detection script can produce.
// Kind naming the field that holds the value.
//
// The zero value reads as "absent".
//
//nolint:recvcheck
type CustomValue struct {
	Kind    CustomKind
	Bool    bool
	Str     string
	Number  float64
	Strings []string
	Floats  []float64
}

// IsSet distinguishes "absent" from "present and false"
func (v CustomValue) IsSet() bool {
	return v.Kind != CustomKindNone
}

// MarshalJSON restores the browser's shape,
// allows DumpFingerprint to show operators what was reported.
func (v CustomValue) MarshalJSON() ([]byte, error) {
	switch v.Kind {
	case CustomKindBool:
		return json.Marshal(v.Bool)
	case CustomKindString:
		return json.Marshal(v.Str)
	case CustomKindNumber:
		return json.Marshal(v.Number)
	case CustomKindStrings:
		return json.Marshal(v.Strings)
	case CustomKindFloats:
		return json.Marshal(v.Floats)
	case CustomKindNone:
		return []byte("null"), nil
	}

	return []byte("null"), nil
}

// UnmarshalJSON turns unrecognized shapes into the
// zero value rather than an error. avoid breaking too easily on bad submission.
func (v *CustomValue) UnmarshalJSON(data []byte) error {
	*v = CustomValue{}

	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch val := raw.(type) {
	case bool:
		v.Kind, v.Bool = CustomKindBool, val
	case string:
		v.Kind, v.Str = CustomKindString, val
	case float64:
		v.Kind, v.Number = CustomKindNumber, val
	case []any:
		v.decodeArray(val)
	}

	return nil
}

// decodeArray is a helper to decode our float/string arrays. A mixed array has
// no proto oneof to land in, so it decodes as absent.
func (v *CustomValue) decodeArray(items []any) {
	if len(items) == 0 {
		return
	}

	switch items[0].(type) {
	case string:
		out := make([]string, 0, len(items))

		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				return
			}

			out = append(out, s)
		}

		v.Kind, v.Strings = CustomKindStrings, out
	case float64:
		out := make([]float64, 0, len(items))

		for _, it := range items {
			f, ok := it.(float64)
			if !ok {
				return
			}

			out = append(out, f)
		}

		v.Kind, v.Floats = CustomKindFloats, out
	}
}
