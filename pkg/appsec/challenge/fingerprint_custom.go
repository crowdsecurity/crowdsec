// fingerprint_custom.go holds the `custom` map that hub-distributed detection
// scripts fill in after fpscanner has run, so new detections and false-positive
// fixes can ship without a release.
//
// The contents are browser-supplied, which shapes everything here: unknown
// shapes decode to the zero value instead of rejecting the submission (as
// flexStruct does in fingerprint_flex.go), and the caps bound what a hostile
// client can push into the sealed cookie.

package challenge

import (
	"encoding/json"
	"sort"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/crowdsecurity/crowdsec/pkg/appsec/challenge/pb"
)

// Caps applied at decode, to bound memory and keep the map small enough that
// the seal-time budget check rarely has anything to drop.
const (
	MaxCustomKeys      = 32
	MaxCustomKeyLen    = 64
	MaxCustomStringLen = 128
	MaxCustomSliceLen  = 16
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
		v.Kind, v.Str = CustomKindString, truncateString(val, MaxCustomStringLen)
	case float64:
		v.Kind, v.Number = CustomKindNumber, val
	case []any:
		v.decodeArray(val)
	}

	return nil
}

// decodeArray is a helper to decode our float/string arrays.
func (v *CustomValue) decodeArray(items []any) {
	if len(items) == 0 {
		return
	}

	if len(items) > MaxCustomSliceLen {
		items = items[:MaxCustomSliceLen]
	}

	switch items[0].(type) {
	case string:
		out := make([]string, 0, len(items))

		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				return
			}

			out = append(out, truncateString(s, MaxCustomStringLen))
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

// truncateString cuts on a rune boundary: these reach proto3 string fields,
// which must hold valid UTF-8.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	cut := s[:maxLen]
	for cut != "" && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}

	return cut
}

// sanitizeCustom drops unmatchable entries and bounds the map, returning how
// many it removed so the caller can log a truncation that would otherwise be
// invisible. Sorting the keys keeps the survivors stable across runs, which map
// iteration order would not.
func sanitizeCustom(in map[string]CustomValue) (map[string]CustomValue, int) {
	if len(in) == 0 {
		return nil, 0
	}

	keys := make([]string, 0, len(in))

	for k, v := range in {
		if validCustomKey(k) && v.IsSet() {
			keys = append(keys, k)
		}
	}

	sort.Strings(keys)

	dropped := len(in) - len(keys)

	if len(keys) > MaxCustomKeys {
		dropped += len(keys) - MaxCustomKeys
		keys = keys[:MaxCustomKeys]
	}

	if len(keys) == 0 {
		return nil, dropped
	}

	out := make(map[string]CustomValue, len(keys))
	for _, k := range keys {
		out[k] = in[k]
	}

	return out, dropped
}

// validCustomKey holds keys to a charset safe for logs, metric labels and rule
// expressions.
func validCustomKey(k string) bool {
	if k == "" || len(k) > MaxCustomKeyLen {
		return false
	}

	for _, c := range []byte(k) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.':
		default:
			return false
		}
	}

	return true
}

// MaxCustomCookieBytes bounds the cookie space custom entries may occupy. A
// realistic envelope runs ~1.8kB against a ~3kB ceiling, so capping well below
// the remainder leaves fpscanner room to grow new signals.
const MaxCustomCookieBytes = 512

// fitCustomToBudget trims the custom map until it fits, returning how many
// entries it removed. Trimming in reverse key order keeps a given submission
// sealing to the same cookie every time.
//
// budget covers the whole fingerprint; the custom map is additionally held to
// MaxCustomCookieBytes.
func fitCustomToBudget(envelope *pb.ChallengeCookie, budget int) int {
	fp := envelope.GetFingerprint()

	custom := fp.GetCustom()
	if len(custom) == 0 {
		return 0
	}

	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	// Measured once and subtracted, rather than restating protobuf's map-framing
	// rules: the rest of the envelope is fixed while entries are dropped.
	fp.Custom = nil
	withoutCustom := proto.Size(envelope)
	fp.Custom = custom

	dropped := 0

	for {
		total := proto.Size(envelope)
		if total <= budget && total-withoutCustom <= MaxCustomCookieBytes {
			break
		}

		if len(keys) == 0 {
			// Nothing left to shed; the caller's size check rejects the envelope.
			fp.Custom = nil

			break
		}

		last := keys[len(keys)-1]
		keys = keys[:len(keys)-1]

		delete(custom, last)

		dropped++
	}

	if len(custom) == 0 {
		fp.Custom = nil
	}

	return dropped
}
