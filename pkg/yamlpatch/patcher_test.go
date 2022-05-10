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
func requireErrorContains(t *testing.T, err error, expectedErr string, testNum int) {
	t.Helper()

	if expectedErr != "" {
		require.ErrorContainsf(t, err, expectedErr, `Error "%s" in test #%d`, err, testNum)

		return
	}

	require.NoErrorf(t, err, `Error "%s" in test #%d`, err, testNum)
}

func TestMergedPatchContent(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tests := []struct {
		base        string
		patch       string
		expected    string
		expectedErr string
	}{
		{
			"notayaml",
			"",
			"",
			"/config.yaml: yaml: unmarshal errors:",
		},
		{
			"notayaml",
			"",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"",
			"notayaml",
			"",
			"/config.yaml.local: yaml: unmarshal errors:",
		},
		{
			"",
			"notayaml",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"{'first':{'one':1,'two':2},'second':{'three':3}}",
			"{'first':{'one':10,'dos':2}}",
			"{'first':{'one':10,'dos':2,'two':2},'second':{'three':3}}",
			"",
		},

		// bools and zero values

		{
			"bool: on",
			"bool: off",
			"bool: false",
			"",
		},
		{
			"bool: off",
			"bool: on",
			"bool: true",
			"",
		},
		{
			"{'bool': 'on'}",
			"{'bool': 'off'}",
			"{'bool': 'off'}",
			"",
		},
		{
			"{'bool': 'off'}",
			"{'bool': 'on'}",
			"{'bool': 'on'}",
			"",
		},
		{
			// bools are bools
			"{'bool': true}",
			"{'bool': false}",
			"{'bool': false}",
			"",
		},
		{
			"{'bool': false}",
			"{'bool': true}",
			"{'bool': true}",
			"",
		},
		{
			"{'string': 'value'}",
			"{'string': ''}",
			"{'string': ''}",
			"",
		},
		{
			"{'sequence': [1, 2]}",
			"{'sequence': []}",
			"{'sequence': []}",
			"",
		},

		// mismatched types

		{
			"map: {'key': 'value'}",
			"map: ['value1', 'value2']",
			"",
			"can't merge a sequence into a mapping",
		},
		{
			"map: {'key': 'value'}",
			"map: 3",
			"",
			"can't merge a scalar into a mapping",
		},
		{
			"sequence: ['value1', 'value2']",
			"sequence: {'key': 'value'}",
			"",
			"can't merge a mapping into a sequence",
		},
		{
			"sequence: ['value1', 'value2']",
			"sequence: 3",
			"",
			"can't merge a scalar into a sequence",
		},
		{
			"scalar: true",
			"scalar: ['value1', 'value2']",
			"",
			"can't merge a sequence into a scalar",
		},
		{
			"scalar: true",
			"scalar: {'key': 'value'}",
			"",
			"can't merge a mapping into a scalar",
		},
	}

	dirPath, err := os.MkdirTemp("", "yamlpatch")
	require.NoError(err)

	defer os.RemoveAll(dirPath)
	configPath := filepath.Join(dirPath, "config.yaml")
	patchPath := filepath.Join(dirPath, "config.yaml.local")

	for testNum, test := range tests {
		err = os.WriteFile(configPath, []byte(test.base), 0o600)
		require.NoError(err)

		err = os.WriteFile(patchPath, []byte(test.patch), 0o600)
		require.NoError(err)

		patcher := yamlpatch.NewPatcher(configPath, ".local")
		patchedBytes, err := patcher.MergedPatchContent()
		requireErrorContains(t, err, test.expectedErr, testNum)
		require.YAMLEq(test.expected, string(patchedBytes))
	}
}

func TestPrependedPatchContent(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tests := []struct {
		base        string
		patch       string
		expected    string
		expectedErr string
	}{
		// we test with scalars here, because YAMLeq does not work
		// with multi-document files, so we need char-to-char comparison
		// which is noisy with sequences and (unordered) mappings
		{
			// newlines are always appended, if missing, by yaml.Marshal()
			"foo: bar",
			"",
			"foo: bar\n",
			"",
		},
		{
			"foo: bar\n",
			"",
			"foo: bar\n",
			"",
		},
		{
			"foo: bar",
			"baz: qux",
			"baz: qux\n---\nfoo: bar\n",
			"",
		},
		{
			"foo: true",
			"foo: false",
			"foo: false\n---\nfoo: true\n",
			"",
		},
		{
			"one: 1\n---\ntwo: 2\n---\none: 3",
			"four: 4\n---\none: 1.1",
			"four: 4\n---\none: 1.1\n---\none: 1\n---\ntwo: 2\n---\none: 3\n",
			"",
		},
		{
			"blablabla",
			"",
			"",
			"/config.yaml: yaml: unmarshal errors:",
		},
		{
			"blablabla",
			"",
			"",
			"cannot unmarshal !!str `blablabla`",
		},
		{
			"",
			"blablabla",
			"",
			"/config.yaml.local: yaml: unmarshal errors:",
		},
		{
			"",
			"blablabla",
			"",
			"cannot unmarshal !!str `blablabla`",
		},
	}

	dirPath, err := os.MkdirTemp("", "yamlpatch")
	require.NoError(err)

	defer os.RemoveAll(dirPath)
	configPath := filepath.Join(dirPath, "config.yaml")
	patchPath := filepath.Join(dirPath, "config.yaml.local")

	for testNum, test := range tests {
		err = os.WriteFile(configPath, []byte(test.base), 0o600)
		require.NoError(err)

		err = os.WriteFile(patchPath, []byte(test.patch), 0o600)
		require.NoError(err)

		patcher := yamlpatch.NewPatcher(configPath, ".local")
		patchedBytes, err := patcher.PrependedPatchContent()
		requireErrorContains(t, err, test.expectedErr, testNum)
		// YAMLeq does not handle multiple documents
		require.Equal(test.expected, string(patchedBytes))
	}
}
