package challenge

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomValueDecode(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want CustomValue
	}{
		{
			name: "bool",
			raw:  `true`,
			want: CustomValue{Kind: CustomKindBool, Bool: true},
		},
		{
			name: "false is set, not absent",
			raw:  `false`,
			want: CustomValue{Kind: CustomKindBool, Bool: false},
		},
		{
			name: "string",
			raw:  `"a91f"`,
			want: CustomValue{Kind: CustomKindString, Str: "a91f"},
		},
		{
			name: "number",
			raw:  `512.5`,
			want: CustomValue{Kind: CustomKindNumber, Number: 512.5},
		},
		{
			name: "string array",
			raw:  `["Arial","Helvetica"]`,
			want: CustomValue{Kind: CustomKindStrings, Strings: []string{"Arial", "Helvetica"}},
		},
		{
			name: "float array",
			raw:  `[12.5,30]`,
			want: CustomValue{Kind: CustomKindFloats, Floats: []float64{12.5, 30}},
		},
		// Shapes a detection script should not produce. They must decode to
		// "absent" rather than fail the submission.
		{name: "object", raw: `{"a":1}`, want: CustomValue{}},
		{name: "null", raw: `null`, want: CustomValue{}},
		{name: "empty array", raw: `[]`, want: CustomValue{}},
		{name: "mixed array", raw: `["a",1]`, want: CustomValue{}},
		{name: "array of objects", raw: `[{"a":1}]`, want: CustomValue{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got CustomValue
			require.NoError(t, json.Unmarshal([]byte(tc.raw), &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCustomValueCaps(t *testing.T) {
	t.Run("long string is truncated", func(t *testing.T) {
		var got CustomValue
		require.NoError(t, json.Unmarshal([]byte(`"`+strings.Repeat("x", 900)+`"`), &got))
		assert.Len(t, got.Str, MaxCustomStringLen)
	})

	t.Run("truncation keeps valid utf8", func(t *testing.T) {
		var got CustomValue
		require.NoError(t, json.Unmarshal([]byte(`"`+strings.Repeat("é", 400)+`"`), &got))
		assert.True(t, utf8.ValidString(got.Str))
		assert.LessOrEqual(t, len(got.Str), MaxCustomStringLen)
	})

	t.Run("long slice is truncated", func(t *testing.T) {
		var got CustomValue
		require.NoError(t, json.Unmarshal([]byte("["+strings.Repeat(`"a",`, 99)+`"a"]`), &got))
		assert.Len(t, got.Strings, MaxCustomSliceLen)
	})
}

func TestCustomValueMarshal(t *testing.T) {
	tests := []struct {
		name string
		in   CustomValue
		want string
	}{
		{name: "bool", in: CustomValue{Kind: CustomKindBool, Bool: true}, want: `true`},
		{name: "false bool", in: CustomValue{Kind: CustomKindBool}, want: `false`},
		{name: "string", in: CustomValue{Kind: CustomKindString, Str: "a91f"}, want: `"a91f"`},
		{name: "number", in: CustomValue{Kind: CustomKindNumber, Number: 512.5}, want: `512.5`},
		{
			name: "strings",
			in:   CustomValue{Kind: CustomKindStrings, Strings: []string{"Arial", "Helvetica"}},
			want: `["Arial","Helvetica"]`,
		},
		{
			name: "floats",
			in:   CustomValue{Kind: CustomKindFloats, Floats: []float64{12.5, 30}},
			want: `[12.5,30]`,
		},
		{name: "unset", in: CustomValue{}, want: `null`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.in)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(out))

			if tc.in.Kind == CustomKindNone {
				return
			}

			var back CustomValue
			require.NoError(t, json.Unmarshal(out, &back))
			assert.Equal(t, tc.in, back)
		})
	}
}

func TestFingerprintCustomDecode(t *testing.T) {
	raw := `{
		"fsid": "FS1_x",
		"custom": {
			"audioCtxNoise": true,
			"audioHash": "a91f",
			"collectMs": 512,
			"fonts": ["Arial","Helvetica"],
			"broken": {"nope": 1}
		}
	}`

	var fp FingerprintData
	require.NoError(t, json.Unmarshal([]byte(raw), &fp))

	assert.True(t, fp.Custom["audioCtxNoise"].Bool)
	assert.Equal(t, "a91f", fp.Custom["audioHash"].Str)
	assert.InDelta(t, 512.0, fp.Custom["collectMs"].Number, 0.001)
	assert.Equal(t, []string{"Arial", "Helvetica"}, fp.Custom["fonts"].Strings)

	assert.False(t, fp.HasCustom("broken"))
	assert.Equal(t, 1, fp.CustomDropped)
	assert.Equal(t, []string{"audioCtxNoise", "audioHash", "collectMs", "fonts"}, fp.CustomKeys())

	// Round-trips in the browser's shape, which is what DumpFingerprint shows.
	out, err := json.Marshal(fp)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"audioCtxNoise":true`)
}

func TestSanitizeCustomKeys(t *testing.T) {
	tests := []struct {
		name string
		key  string
		keep bool
	}{
		{name: "alnum", key: "audioCtxNoise", keep: true},
		{name: "underscore dash dot", key: "a_b-c.d", keep: true},
		{name: "at the limit", key: strings.Repeat("a", MaxCustomKeyLen), keep: true},
		{name: "empty", key: "", keep: false},
		{name: "space", key: "has space", keep: false},
		{name: "quote", key: `a"b`, keep: false},
		{name: "non-ascii", key: "clé", keep: false},
		{name: "too long", key: strings.Repeat("a", MaxCustomKeyLen+1), keep: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, dropped := sanitizeCustom(map[string]CustomValue{
				tc.key: {Kind: CustomKindBool, Bool: true},
			})

			if tc.keep {
				assert.Len(t, got, 1)
				assert.Equal(t, 0, dropped)

				return
			}

			assert.Empty(t, got)
			assert.Equal(t, 1, dropped)
		})
	}
}

// Which entries survive an over-long map must not depend on map iteration
// order, or the same submission would seal to a different cookie each time.
func TestSanitizeCustomIsDeterministic(t *testing.T) {
	in := make(map[string]CustomValue, MaxCustomKeys*2)
	for i := range MaxCustomKeys * 2 {
		in[string(rune('a'+i/26))+string(rune('a'+i%26))] = CustomValue{Kind: CustomKindBool, Bool: true}
	}

	first, dropped := sanitizeCustom(in)
	require.Len(t, first, MaxCustomKeys)
	require.Equal(t, MaxCustomKeys, dropped)

	for range 20 {
		again, _ := sanitizeCustom(in)
		require.Equal(t, first, again)
	}
}

// Storing CustomValue by value is what lets rules read an unknown key without a
// presence check; a pointer element would hand them a nil to dereference.
func TestCustomIsSafeToReadFromExpr(t *testing.T) {
	fp := &FingerprintData{
		Custom: map[string]CustomValue{
			"audioCtxNoise": {Kind: CustomKindBool, Bool: true},
			"audioHash":     {Kind: CustomKindString, Str: "a91f"},
			"collectMs":     {Kind: CustomKindNumber, Number: 512},
			"fonts":         {Kind: CustomKindStrings, Strings: []string{"Arial"}},
		},
	}

	tests := []struct {
		expr string
		want any
	}{
		{expr: `fingerprint.Custom["audioCtxNoise"].Bool`, want: true},
		{expr: `fingerprint.Custom["audioHash"].Str == "a91f"`, want: true},
		{expr: `fingerprint.Custom["collectMs"].Number > 500`, want: true},
		{expr: `"Arial" in fingerprint.Custom["fonts"].Strings`, want: true},
		{expr: `fingerprint.HasCustom("audioHash")`, want: true},
		{expr: `fingerprint.Custom["neverSet"].Bool`, want: false},
		{expr: `fingerprint.Custom["neverSet"].Str == ""`, want: true},
		{expr: `len(fingerprint.Custom["neverSet"].Strings) == 0`, want: true},
		{expr: `fingerprint.HasCustom("neverSet")`, want: false},
	}

	env := map[string]any{"fingerprint": fp}

	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			prog, err := expr.Compile(tc.expr, expr.Env(env))
			require.NoError(t, err)

			out, err := expr.Run(prog, env)
			require.NoError(t, err)
			assert.Equal(t, tc.want, out)
		})
	}

	// Same guarantee on a fingerprint that carries no custom map at all.
	empty := map[string]any{"fingerprint": &FingerprintData{}}

	prog, err := expr.Compile(`fingerprint.Custom["anything"].Bool`, expr.Env(empty))
	require.NoError(t, err)

	out, err := expr.Run(prog, empty)
	require.NoError(t, err)
	assert.Equal(t, false, out)
}
