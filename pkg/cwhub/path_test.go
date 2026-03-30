package cwhub

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveSymlink_Relative(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.yaml")
	b := filepath.Join(tmp, "dir", "b.yaml")
	require.NoError(t, os.Mkdir(filepath.Dir(b), 0o755))
	require.NoError(t, os.WriteFile(b, []byte("ok"), 0o644))
	require.NoError(t, os.Symlink("dir/b.yaml", a)) // relative link

	got, err := resolveSymlink(a)
	require.NoError(t, err)
	require.Equal(t, b, got)
}
