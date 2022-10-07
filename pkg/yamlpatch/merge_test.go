// Copyright (c) 2018 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package yamlpatch

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

func trimcr(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

func mustRead(t testing.TB, fname string) []byte {
	contents, err := os.ReadFile(fname)
	require.NoError(t, err, "failed to read file: %s", fname)
	return contents
}

func dump(t testing.TB, actual, expected string) {
	// It's impossible to debug YAML if the actual and expected values are
	// printed on a single line.
	t.Logf("Actual:\n\n%s\n\n", actual)
	t.Logf("Expected:\n\n%s\n\n", expected)
}

func strip(s string) string {
	// It's difficult to write string constants that are valid YAML. Normalize
	// strings for ease of testing.
	s = strings.TrimSpace(s)
	s = strings.Replace(s, "\t", "  ", -1)
	return s
}

func canonicalize(t testing.TB, s string) string {
	// round-trip to canonicalize formatting
	var i interface{}
	require.NoError(t,
		yaml.Unmarshal([]byte(strip(s)), &i),
		"canonicalize: couldn't unmarshal YAML",
	)
	formatted, err := yaml.Marshal(i)
	require.NoError(t, err, "canonicalize: couldn't marshal YAML")
	return string(bytes.TrimSpace(formatted))
}

func unmarshal(t testing.TB, s string) interface{} {
	var i interface{}
	require.NoError(t, yaml.Unmarshal([]byte(strip(s)), &i), "unmarshaling failed")
	return i
}

func succeeds(t testing.TB, strict bool, left, right, expect string) {
	l, r := unmarshal(t, left), unmarshal(t, right)
	m, err := merge(l, r, strict)
	require.NoError(t, err, "merge failed")

	actualBytes, err := yaml.Marshal(m)
	require.NoError(t, err, "couldn't marshal merged structure")
	actual := canonicalize(t, string(actualBytes))
	expect = canonicalize(t, expect)
	if !assert.Equal(t, expect, actual) {
		dump(t, actual, expect)
	}
}

func fails(t testing.TB, strict bool, left, right string) {
	_, err := merge(unmarshal(t, left), unmarshal(t, right), strict)
	assert.Error(t, err, "merge succeeded")
}

func TestIntegration(t *testing.T) {
	base := mustRead(t, "testdata/base.yaml")
	prod := mustRead(t, "testdata/production.yaml")
	expect := mustRead(t, "testdata/expect.yaml")

	merged, err := YAML([][]byte{base, prod}, true /* strict */)
	require.NoError(t, err, "merge failed")

	if !assert.Equal(t, trimcr(string(expect)), merged.String(), "unexpected contents") {
		dump(t, merged.String(), string(expect))
	}
}

func TestEmpty(t *testing.T) {
	full := []byte("foo: bar\n")
	null := []byte("~")

	tests := []struct {
		desc    string
		sources [][]byte
		expect  string
	}{
		{"empty base", [][]byte{nil, full}, string(full)},
		{"empty override", [][]byte{full, nil}, string(full)},
		{"both empty", [][]byte{nil, nil}, ""},
		{"null base", [][]byte{null, full}, string(full)},
		{"null override", [][]byte{full, null}, "null\n"},
		{"empty base and null override", [][]byte{nil, null}, "null\n"},
		{"null base and empty override", [][]byte{null, nil}, "null\n"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc, func(t *testing.T) {
			merged, err := YAML(tt.sources, true /* strict */)
			require.NoError(t, err, "merge failed")
			assert.Equal(t, tt.expect, merged.String(), "wrong contents after merge")
		})
	}
}

func TestSuccess(t *testing.T) {
	left := `
fun: [maserati, porsche]
practical: {toyota: camry, honda: accord}
occupants:
  honda: {driver: jane, backseat: [nate]}
	`
	right := `
fun: [lamborghini, porsche]
practical: {honda: civic, nissan: altima}
occupants:
  honda: {passenger: arthur, backseat: [nora]}
	`
	expect := `
fun: [lamborghini, porsche]
practical: {toyota: camry, honda: civic, nissan: altima}
occupants:
  honda: {passenger: arthur, driver: jane, backseat: [nora]}
  `
	succeeds(t, true, left, right, expect)
	succeeds(t, false, left, right, expect)
}

func TestErrors(t *testing.T) {
	check := func(t testing.TB, strict bool, sources ...[]byte) error {
		_, err := YAML(sources, strict)
		return err
	}
	t.Run("tabs in source", func(t *testing.T) {
		src := []byte("foo:\n\tbar:baz")
		assert.Error(t, check(t, false, src), "expected error in permissive mode")
		assert.Error(t, check(t, true, src), "expected error in strict mode")
	})

	t.Run("duplicated keys", func(t *testing.T) {
		src := []byte("{foo: bar, foo: baz}")
		assert.NoError(t, check(t, false, src), "expected success in permissive mode")
		assert.Error(t, check(t, true, src), "expected error in permissive mode")
	})

	t.Run("merge error", func(t *testing.T) {
		left := []byte("foo: [1, 2]")
		right := []byte("foo: {bar: baz}")
		assert.NoError(t, check(t, false, left, right), "expected success in permissive mode")
		assert.Error(t, check(t, true, left, right), "expected error in strict mode")
	})
}

func TestMismatchedTypes(t *testing.T) {
	tests := []struct {
		desc        string
		left, right string
	}{
		{"sequence and mapping", "[one, two]", "{foo: bar}"},
		{"sequence and scalar", "[one, two]", "foo"},
		{"mapping and scalar", "{foo: bar}", "foo"},
		{"nested", "{foo: [one, two]}", "{foo: bar}"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.desc+" strict", func(t *testing.T) {
			fails(t, true, tt.left, tt.right)
		})
		t.Run(tt.desc+" permissive", func(t *testing.T) {
			// prefer the higher-priority value
			succeeds(t, false, tt.left, tt.right, tt.right)
		})
	}
}

func TestBooleans(t *testing.T) {
	// YAML helpfully interprets many strings as Booleans.
	tests := []struct {
		in, out string
	}{
		{"yes", "true"},
		{"YES", "true"},
		{"on", "true"},
		{"ON", "true"},
		{"no", "false"},
		{"NO", "false"},
		{"off", "false"},
		{"OFF", "false"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			succeeds(t, true, "", tt.in, tt.out)
			succeeds(t, false, "", tt.in, tt.out)
		})
	}
}

func TestExplicitNil(t *testing.T) {
	base := `foo: {one: two}`
	override := `foo: ~`
	expect := `foo: ~`
	succeeds(t, true, base, override, expect)
	succeeds(t, false, base, override, expect)
}
