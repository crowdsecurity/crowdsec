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
		expected []string
	}{
		{
			name:     "Path within baseDir",
			path:     "/home/user/project/src/file.go",
			baseDir:  "/home/user/project",
			expected: []string{"src", "file.go"},
		},
		{
			name:     "Path is baseDir",
			path:     "/home/user/project",
			baseDir:  "/home/user/project",
			expected: []string{},
		},
		{
			name:     "Path outside baseDir",
			path:     "/home/user/otherproject/src/file.go",
			baseDir:  "/home/user/project",
			expected: []string{},
		},
		{
			name:     "Path is subdirectory of baseDir",
			path:     "/home/user/project/src/",
			baseDir:  "/home/user/project",
			expected: []string{"src"},
		},
		{
			name:     "Relative paths",
			path:     "project/src/file.go",
			baseDir:  "project",
			expected: []string{"src", "file.go"},
		},
		{
			name:     "BaseDir with trailing slash",
			path:     "/home/user/project/src/file.go",
			baseDir:  "/home/user/project/",
			expected: []string{"src", "file.go"},
		},
		{
			name:     "Empty baseDir",
			path:     "/home/user/project/src/file.go",
			baseDir:  "",
			expected: []string{},
		},
		{
			name:     "Empty path",
			path:     "",
			baseDir:  "/home/user/project",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := relativePathComponents(tt.path, tt.baseDir)
			assert.Equal(t, tt.expected, result)
		})
	}
}
