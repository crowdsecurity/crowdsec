package csplugin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestListFilesAtPath(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(filepath.Join(dir, "notification-gitter"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	f, err = os.Create(filepath.Join(dir, "slack"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	err = os.Mkdir(filepath.Join(dir, "somedir"), 0o755)
	require.NoError(t, err)

	f, err = os.Create(filepath.Join(dir, "somedir", "inner"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	tests := []struct {
		name        string
		path        string
		want        []string
		expectedErr string
	}{
		{
			name: "valid directory",
			path: dir,
			want: []string{
				filepath.Join(dir, "notification-gitter"),
				filepath.Join(dir, "slack"),
			},
		},
		{
			name:        "invalid directory",
			path:        "./foo/bar/",
			expectedErr: "open ./foo/bar/: " + cstest.PathNotFoundMessage,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listFilesAtPath(tc.path)
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}
