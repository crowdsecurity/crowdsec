package cwhub

import (
	"path/filepath"
	"strings"
)

// relativePathComponents returns the list of path components after baseDir.
// If path is not inside baseDir, it returns an empty slice.
func relativePathComponents(path string, baseDir string) []string {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return []string{}
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return []string{}
	}

	// is path inside baseDir?
	relPath, err := filepath.Rel(absBaseDir, absPath)
	if err != nil || strings.HasPrefix(relPath, "..") || relPath == "." {
		return []string{}
	}

	return strings.Split(relPath, string(filepath.Separator))
}
