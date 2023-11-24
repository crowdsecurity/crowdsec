package hubtest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckPathNotContained(t *testing.T) {
	require.NoError(t, checkPathNotContained("/foo", "/bar"))
	require.NoError(t, checkPathNotContained("/foo/bar", "/foo"))
	require.NoError(t, checkPathNotContained("/foo/bar", "/"))
	require.NoError(t, checkPathNotContained("/path/to/somewhere", "/path/to/somewhere-else"))
	require.NoError(t, checkPathNotContained("~/.local/path/to/somewhere", "~/.local/path/to/somewhere-else"))
	require.Error(t, checkPathNotContained("/foo", "/foo/bar"))
	require.Error(t, checkPathNotContained("/", "/foo"))
	require.Error(t, checkPathNotContained("/", "/foo/bar/baz"))
}
