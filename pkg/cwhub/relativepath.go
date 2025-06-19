package cwhub

import (
	"path/filepath"
	"strings"
)

// relativePathComponents returns the list of path components after baseDir,
// and a boolean indicating whether path is inside baseDir at all.
func relativePathComponents(path string, baseDir string) ([]string, bool) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		// cwd disappeared??
		return nil, false
	}

	absBaseDir, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, false
	}

	// is path inside baseDir?
	relPath, err := filepath.Rel(absBaseDir, absPath)
	if err != nil || strings.HasPrefix(relPath, "..") || relPath == "." {
		return nil, false
	}

	return strings.Split(relPath, string(filepath.Separator)), true
}
