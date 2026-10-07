package exprhelpers

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

// writeMacroItems writes one file per item, the map key being the item name.
func writeMacroItems(t *testing.T, items map[string]string) []macroFile {
	t.Helper()

	dir := t.TempDir()
	files := []macroFile{}

	for name, content := range items {
		path := filepath.Join(dir, name+".yaml")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		files = append(files, macroFile{item: name, path: path})
	}

	slices.SortFunc(files, func(a, b macroFile) int { return cmp.Compare(a.item, b.item) })

	return files
}

func loadTestMacros(t *testing.T, items map[string]string) error {
	t.Helper()
	t.Cleanup(func() { macros = nil })

	_, err := loadMacroFiles(writeMacroItems(t, items))

	return err
}

func TestMacroExpansion(t *testing.T) {
	err := loadTestMacros(t, map[string]string{
		"test/a": `
name: test/a
description: other keys are ignored
macros:
  IsFoo: foo == 'true' && bar == 'true'
  FooOrBar: foo == 'true' || bar == 'true'
`,
		"test/b": `
macros:
  IsFooAndBaz: IsFoo() && baz
  Plus1: n + 1
`,
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		expr        string
		env         map[string]any
		want        any
		expectedErr string
	}{
		{
			name: "simple",
			expr: "IsFoo() && baz",
			env:  map[string]any{"foo": "true", "bar": "true", "baz": true},
			want: true,
		},
		{
			name: "simple false",
			expr: "IsFoo()",
			env:  map[string]any{"foo": "true", "bar": "false"},
			want: false,
		},
		{
			// a textual replacement would give !foo == 'true' || bar == 'true'
			name: "negation applies to the whole macro",
			expr: "!FooOrBar()",
			env:  map[string]any{"foo": "true", "bar": "true"},
			want: false,
		},
		{
			name: "nested",
			expr: "IsFooAndBaz()",
			env:  map[string]any{"foo": "true", "bar": "true", "baz": false},
			want: false,
		},
		{
			name: "same macro twice",
			expr: "IsFoo() == IsFoo()",
			env:  map[string]any{"foo": "true", "bar": "true"},
			want: true,
		},
		{
			name: "macro inside predicate",
			expr: "all([1, 2], {IsFoo()})",
			env:  map[string]any{"foo": "true", "bar": "true"},
			want: true,
		},
		{
			name: "int env",
			expr: "Plus1()",
			env:  map[string]any{"n": 1},
			want: 2,
		},
		{
			name: "float env",
			expr: "Plus1()",
			env:  map[string]any{"n": 1.5},
			want: 2.5,
		},
		{
			name:        "macros take no arguments",
			expr:        "IsFoo(1)",
			env:         map[string]any{"foo": "true", "bar": "true"},
			expectedErr: "unknown name IsFoo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program, err := expr.Compile(tc.expr, GetExprOptions(tc.env)...)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			got, err := expr.Run(program, tc.env)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestLoadMacrosErrors(t *testing.T) {
	tests := []struct {
		name        string
		items       map[string]string
		expectedErr string
	}{
		{
			name:  "no items",
			items: map[string]string{},
		},
		{
			name:        "invalid yaml",
			items:       map[string]string{"a": "- not a map"},
			expectedErr: "a.yaml: yaml: unmarshal errors",
		},
		{
			name:        "missing macros key",
			items:       map[string]string{"a": "Foo: true"},
			expectedErr: "a.yaml: no macros defined under the 'macros' key",
		},
		{
			name:        "duplicate across items",
			items:       map[string]string{"a": "macros: {Foo: true}", "b": "macros: {Foo: false}"},
			expectedErr: `macro "Foo" is defined by both a and b`,
		},
		{
			name:        "invalid name",
			items:       map[string]string{"a": "macros: {'Foo-Bar': true}"},
			expectedErr: `macro "Foo-Bar" (a): invalid name`,
		},
		{
			name:        "builtin conflict",
			items:       map[string]string{"a": "macros: {len: true}"},
			expectedErr: `macro "len" (a): conflicts with a builtin function`,
		},
		{
			name:        "crowdsec function conflict",
			items:       map[string]string{"a": "macros: {Upper: true}"},
			expectedErr: `macro "Upper" (a): conflicts with a crowdsec function`,
		},
		{
			name:        "empty expression",
			items:       map[string]string{"a": "macros: {Foo: ''}"},
			expectedErr: `macro "Foo" (a): empty expression`,
		},
		{
			name:        "syntax error",
			items:       map[string]string{"a": "macros: {Foo: a &&}"},
			expectedErr: `macro "Foo" (a): unexpected token EOF`,
		},
		{
			name:        "self recursion",
			items:       map[string]string{"a": "macros: {Foo: Foo() && true}"},
			expectedErr: `macro "Foo": recursive definition (Foo -> Foo)`,
		},
		{
			// cycles across items too
			name:        "mutual recursion",
			items:       map[string]string{"a": "macros: {A: B(), B: C()}", "b": "macros: {C: A()}"},
			expectedErr: `macro "A": recursive definition (A -> B -> C -> A)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := loadTestMacros(t, tc.items)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestLoadMacrosReplacesPrevious(t *testing.T) {
	require.NoError(t, loadTestMacros(t, map[string]string{"a": "macros: {Foo: true}"}))

	_, err := expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	require.NoError(t, err)

	// a failed load keeps the previous macros
	_, err = loadMacroFiles(writeMacroItems(t, map[string]string{"a": "macros: {Foo: Foo()}"}))
	require.Error(t, err)

	_, err = expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	require.NoError(t, err)

	// no hub, no macros
	n, err := LoadMacros(nil)
	require.NoError(t, err)
	require.Zero(t, n)

	_, err = expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	cstest.RequireErrorContains(t, err, "unknown name Foo")
}

func TestMacroConcurrentCompile(t *testing.T) { //nolint:tparallel // mutates the package-level macros
	require.NoError(t, loadTestMacros(t, map[string]string{"a": "macros: {IsFoo: foo == 'true' && n > 0}"}))

	for i := range 8 {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			env := map[string]any{"foo": "true", "n": i}
			program, err := expr.Compile("IsFoo()", GetExprOptions(env)...)
			require.NoError(t, err)

			got, err := expr.Run(program, env)
			require.NoError(t, err)
			require.Equal(t, i > 0, got)
		})
	}
}

func TestMacroItems(t *testing.T) {
	require.NoError(t, loadTestMacros(t, map[string]string{
		"test/a": "macros: {A: B() || C()}",
		"test/b": "macros: {B: D()}",
		"test/c": "macros: {C: true, Unused: true}",
		"test/d": "macros: {D: true}",
		"test/e": "macros: {E: true}",
	}))

	tests := []struct {
		name        string
		expr        string
		want        []string
		expectedErr string
	}{
		{
			name: "no macros",
			expr: "evt.Line.Raw != ''",
			want: []string{},
		},
		{
			name: "direct",
			expr: "E() && true",
			want: []string{"test/e"},
		},
		{
			name: "through other macros",
			expr: "A()",
			want: []string{"test/a", "test/b", "test/c", "test/d"},
		},
		{
			name: "same item twice",
			expr: "C() || Unused()",
			want: []string{"test/c"},
		},
		{
			name: "call with arguments is not a macro",
			expr: "E(1)",
			want: []string{},
		},
		{
			name:        "syntax error",
			expr:        "A() &&",
			expectedErr: "unexpected token EOF",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MacroItems(tc.expr)
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.want, got)
		})
	}
}
