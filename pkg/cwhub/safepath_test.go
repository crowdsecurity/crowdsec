package cwhub

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func TestSafePath(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "app")

	tests := []struct {
		name       string
		baseDir    string
		relPath    string
		want       string
		wantErr    string
	}{
		{
			name:    "AbsoluteRelPath",
			baseDir: base,
			relPath: string(os.PathSeparator) + filepath.Join("etc", "passwd"),
			wantErr: "must be a relative path",
		},
		{
			name:    "InsideBase_SimpleFile",
			baseDir: base,
			relPath: "file.txt",
			want: filepath.Join(parent, "app", "file.txt"),
		},
		{
			name:    "InsideBase_Nested",
			baseDir: base,
			relPath: filepath.Join("subdir", "child.txt"),
			want: filepath.Join(parent, "app", "subdir", "child.txt"),
		},
		{
			name:    "Escape_ParentDirectory",
			baseDir: base,
			relPath: filepath.Join("..", "etc", "passwd"),
			wantErr: "path escapes base directory",
		},
		{
			name:    "Escape_SiblingPrefix",
			baseDir: base,
			relPath: filepath.Join("..", "application", "foo.txt"),
			wantErr: "path escapes base directory",
		},
		{
			name:    "Escape_Middle",
			baseDir: base,
			relPath: filepath.Join("foo", "..", "..", "application", "foo.txt"),
			wantErr: "path escapes base directory",
		},
		{
			name:    "ComplexCleanInside",
			baseDir: base,
			relPath: filepath.Join("subdir", "..", "subdir2", "file.txt"),
			want: filepath.Join(parent, "app", "subdir2", "file.txt"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SafePath(tc.baseDir, tc.relPath)
			cstest.RequireErrorContains(t, err, tc.wantErr)
			if tc.wantErr != "" {
				return
			}

			assert.True(t, filepath.IsAbs(got), "SafePath should return an absolute path")
			assert.Equal(t, tc.want, got)
		})
	}
}
