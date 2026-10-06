package exprhelpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/expr-lang/expr"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func writeMacroFiles(t *testing.T, files map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}

	return dir
}

func loadTestMacros(t *testing.T, files map[string]string) error {
	t.Helper()
	t.Cleanup(func() { macros = nil })

	return LoadMacros(writeMacroFiles(t, files))
}

func TestMacroExpansion(t *testing.T) {
	err := loadTestMacros(t, map[string]string{
		"a.yaml": `
IsFoo: foo == 'true' && bar == 'true'
FooOrBar: foo == 'true' || bar == 'true'
`,
		"b.yml": `
IsFooAndBaz: IsFoo() && baz
Plus1: n + 1
`,
		"ignored.txt": `NotLoaded: true`,
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
		{
			name:        "non-yaml files are ignored",
			expr:        "NotLoaded()",
			env:         map[string]any{},
			expectedErr: "unknown name NotLoaded",
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
		files       map[string]string
		expectedErr string
	}{
		{
			name:  "no files",
			files: map[string]string{},
		},
		{
			name:        "invalid yaml",
			files:       map[string]string{"a.yaml": "- not a map"},
			expectedErr: "a.yaml: yaml: unmarshal errors",
		},
		{
			name:        "duplicate across files",
			files:       map[string]string{"a.yaml": "Foo: true", "b.yaml": "Foo: false"},
			expectedErr: `b.yaml: macro "Foo" is already defined`,
		},
		{
			name:        "invalid name",
			files:       map[string]string{"a.yaml": "'Foo-Bar': true"},
			expectedErr: `macro "Foo-Bar": invalid name`,
		},
		{
			name:        "builtin conflict",
			files:       map[string]string{"a.yaml": "len: true"},
			expectedErr: `macro "len": conflicts with a builtin function`,
		},
		{
			name:        "crowdsec function conflict",
			files:       map[string]string{"a.yaml": "Upper: true"},
			expectedErr: `macro "Upper": conflicts with a crowdsec function`,
		},
		{
			name:        "empty expression",
			files:       map[string]string{"a.yaml": "Foo: ''"},
			expectedErr: `macro "Foo": empty expression`,
		},
		{
			name:        "syntax error",
			files:       map[string]string{"a.yaml": "Foo: a &&"},
			expectedErr: `macro "Foo": unexpected token EOF`,
		},
		{
			name:        "self recursion",
			files:       map[string]string{"a.yaml": "Foo: Foo() && true"},
			expectedErr: `macro "Foo": recursive definition (Foo -> Foo)`,
		},
		{
			name:        "mutual recursion",
			files:       map[string]string{"a.yaml": "A: B()\nB: C()\nC: A()"},
			expectedErr: `macro "A": recursive definition (A -> B -> C -> A)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := loadTestMacros(t, tc.files)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestLoadMacrosReplacesPrevious(t *testing.T) {
	require.NoError(t, loadTestMacros(t, map[string]string{"a.yaml": "Foo: true"}))

	_, err := expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	require.NoError(t, err)

	// a failed load keeps the previous macros
	require.Error(t, LoadMacros(writeMacroFiles(t, map[string]string{"a.yaml": "Foo: Foo()"})))

	_, err = expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	require.NoError(t, err)

	// a reload without the file drops the macro
	require.NoError(t, LoadMacros(filepath.Join(t.TempDir(), "missing")))

	_, err = expr.Compile("Foo()", GetExprOptions(map[string]any{})...)
	cstest.RequireErrorContains(t, err, "unknown name Foo")
}

func TestMacroConcurrentCompile(t *testing.T) { //nolint:tparallel // mutates the package-level macros
	require.NoError(t, loadTestMacros(t, map[string]string{"a.yaml": "IsFoo: foo == 'true' && n > 0"}))

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
