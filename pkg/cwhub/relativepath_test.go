package cwhub

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRelativePathComponents(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		baseDir  string
		wantSubs []string
		wantOk   bool
	}{
		{
			name:     "Path within baseDir",
			path:     "/home/user/project/src/file.go",
			baseDir:  "/home/user/project",
			wantSubs: []string{"src", "file.go"},
			wantOk:   true,
		},
		{
			name:     "Path is baseDir",
			path:     "/home/user/project",
			baseDir:  "/home/user/project",
			wantSubs: nil,
			wantOk:   false,
		},
		{
			name:     "Path outside baseDir",
			path:     "/home/user/otherproject/src/file.go",
			baseDir:  "/home/user/project",
			wantSubs: nil,
			wantOk:   false,
		},
		{
			name:     "Path is subdirectory of baseDir",
			path:     "/home/user/project/src/",
			baseDir:  "/home/user/project",
			wantSubs: []string{"src"},
			wantOk:   true,
		},
		{
			name:     "Relative paths",
			path:     "project/src/file.go",
			baseDir:  "project",
			wantSubs: []string{"src", "file.go"},
			wantOk:   true,
		},
		{
			name:     "BaseDir with trailing slash",
			path:     "/home/user/project/src/file.go",
			baseDir:  "/home/user/project/",
			wantSubs: []string{"src", "file.go"},
			wantOk:   true,
		},
		{
			name:     "Empty baseDir",
			path:     "/home/user/project/src/file.go",
			baseDir:  "",
			wantSubs: nil,
			wantOk:   false,
		},
		{
			name:     "Empty path",
			path:     "",
			baseDir:  "/home/user/project",
			wantSubs: nil,
			wantOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := relativePathComponents(tt.path, tt.baseDir)
			assert.Equal(t, tt.wantSubs, got)
			assert.Equal(t, tt.wantOk, ok)
		})
	}
}
