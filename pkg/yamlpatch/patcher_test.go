package yamlpatch_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/yamlpatch"
	"github.com/stretchr/testify/require"
)

// similar to the one in cstest, but with test number too. We cannot import
// cstest here because of circular dependency.
func requireErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		require.ErrorContains(t, err, expectedErr)

		return
	}

	require.NoError(t, err)
}

func TestMergedPatchContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		base        string
		patch       string
		expected    string
		expectedErr string
	}{
		{
			"invalid yaml in base",
			"notayaml",
			"",
			"",
			"/config.yaml: yaml: unmarshal errors:",
		},
		{
			"invalid yaml in base (detailed message)",
			"notayaml",
			"",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"invalid yaml in patch",
			"",
			"notayaml",
			"",
			"/config.yaml.local: yaml: unmarshal errors:",
		},
		{
			"invalid yaml in patch (detailed message)",
			"",
			"notayaml",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"basic merge",
			"{'first':{'one':1,'two':2},'second':{'three':3}}",
			"{'first':{'one':10,'dos':2}}",
			"{'first':{'one':10,'dos':2,'two':2},'second':{'three':3}}",
			"",
		},

		// bools and zero values; here the "mergo" package had issues
		// so we used something simpler.

		{
			"bool merge - off if false",
			"bool: on",
			"bool: off",
			"bool: false",
			"",
		},
		{
			"bool merge - on is true",
			"bool: off",
			"bool: on",
			"bool: true",
			"",
		},
		{
			"string is not a bool - on to off",
			"{'bool': 'on'}",
			"{'bool': 'off'}",
			"{'bool': 'off'}",
			"",
		},
		{
			"string is not a bool - off to on",
			"{'bool': 'off'}",
			"{'bool': 'on'}",
			"{'bool': 'on'}",
			"",
		},
		{
			"bool merge - true to false",
			"{'bool': true}",
			"{'bool': false}",
			"{'bool': false}",
			"",
		},
		{
			"bool merge - false to true",
			"{'bool': false}",
			"{'bool': true}",
			"{'bool': true}",
			"",
		},
		{
			"string merge - value to value",
			"{'string': 'value'}",
			"{'string': ''}",
			"{'string': ''}",
			"",
		},
		{
			"sequence merge - value to empty",
			"{'sequence': [1, 2]}",
			"{'sequence': []}",
			"{'sequence': []}",
			"",
		},
		{
			"map merge - value to value",
			"{'map': {'one': 1, 'two': 2}}",
			"{'map': {}}",
			"{'map': {'one': 1, 'two': 2}}",
			"",
		},

		// mismatched types

		{
			"can't merge a sequence into a mapping",
			"map: {'key': 'value'}",
			"map: ['value1', 'value2']",
			"",
			"can't merge a sequence into a mapping",
		},
		{
			"can't merge a scalar into a mapping",
			"map: {'key': 'value'}",
			"map: 3",
			"",
			"can't merge a scalar into a mapping",
		},
		{
			"can't merge a mapping into a sequence",
			"sequence: ['value1', 'value2']",
			"sequence: {'key': 'value'}",
			"",
			"can't merge a mapping into a sequence",
		},
		{
			"can't merge a scalar into a sequence",
			"sequence: ['value1', 'value2']",
			"sequence: 3",
			"",
			"can't merge a scalar into a sequence",
		},
		{
			"can't merge a sequence into a scalar",
			"scalar: true",
			"scalar: ['value1', 'value2']",
			"",
			"can't merge a sequence into a scalar",
		},
		{
			"can't merge a mapping into a scalar",
			"scalar: true",
			"scalar: {'key': 'value'}",
			"",
			"can't merge a mapping into a scalar",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dirPath, err := os.MkdirTemp("", "yamlpatch")
			require.NoError(t, err)

			defer os.RemoveAll(dirPath)

			configPath := filepath.Join(dirPath, "config.yaml")
			patchPath := filepath.Join(dirPath, "config.yaml.local")
			err = os.WriteFile(configPath, []byte(tc.base), 0o600)
			require.NoError(t, err)

			err = os.WriteFile(patchPath, []byte(tc.patch), 0o600)
			require.NoError(t, err)

			patcher := yamlpatch.NewPatcher(configPath, ".local")
			patchedBytes, err := patcher.MergedPatchContent()
			requireErrorContains(t, err, tc.expectedErr)
			require.YAMLEq(t, tc.expected, string(patchedBytes))
		})
	}
}

func TestPrependedPatchContent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		base        string
		patch       string
		expected    string
		expectedErr string
	}{
		// we test with scalars here, because YAMLeq does not work
		// with multi-document files, so we need char-to-char comparison
		// which is noisy with sequences and (unordered) mappings
		{
			"newlines are always appended, if missing, by yaml.Marshal()",
			"foo: bar",
			"",
			"foo: bar\n",
			"",
		},
		{
			"prepend empty document",
			"foo: bar\n",
			"",
			"foo: bar\n",
			"",
		},
		{
			"prepend a document to another",
			"foo: bar",
			"baz: qux",
			"baz: qux\n---\nfoo: bar\n",
			"",
		},
		{
			"prepend document with same key",
			"foo: true",
			"foo: false",
			"foo: false\n---\nfoo: true\n",
			"",
		},
		{
			"prepend multiple documents",
			"one: 1\n---\ntwo: 2\n---\none: 3",
			"four: 4\n---\none: 1.1",
			"four: 4\n---\none: 1.1\n---\none: 1\n---\ntwo: 2\n---\none: 3\n",
			"",
		},
		{
			"invalid yaml in base",
			"blablabla",
			"",
			"",
			"/config.yaml: yaml: unmarshal errors:",
		},
		{
			"invalid yaml in base (detailed message)",
			"blablabla",
			"",
			"",
			"cannot unmarshal !!str `blablabla`",
		},
		{
			"invalid yaml in patch",
			"",
			"blablabla",
			"",
			"/config.yaml.local: yaml: unmarshal errors:",
		},
		{
			"invalid yaml in patch (detailed message)",
			"",
			"blablabla",
			"",
			"cannot unmarshal !!str `blablabla`",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dirPath, err := os.MkdirTemp("", "yamlpatch")
			require.NoError(t, err)

			defer os.RemoveAll(dirPath)

			configPath := filepath.Join(dirPath, "config.yaml")
			patchPath := filepath.Join(dirPath, "config.yaml.local")

			err = os.WriteFile(configPath, []byte(tc.base), 0o600)
			require.NoError(t, err)

			err = os.WriteFile(patchPath, []byte(tc.patch), 0o600)
			require.NoError(t, err)

			patcher := yamlpatch.NewPatcher(configPath, ".local")
			patchedBytes, err := patcher.PrependedPatchContent()
			requireErrorContains(t, err, tc.expectedErr)
			// YAMLeq does not handle multiple documents
			require.Equal(t, tc.expected, string(patchedBytes))
		})
	}
}
