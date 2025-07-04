package cwhub

import (
	"fmt"
	"path/filepath"
	"os"
	"strings"
)

// SafePath returns a joined path and ensures that it does not escape the base directory.
// We can't use the traversal-resistant methods in "os.Root" because install link targets are outside their base directories
// (installdir -> hubdir), which would not be allowed if hubdir is not inside installdir.
func SafePath(baseDir, relPath string) (string, error) {
	absBase, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return "", err
	}

	if filepath.IsAbs(relPath) ||
		// on windows, IsAbs fails for paths beginning with "/", since it's the root of the drive
		strings.HasPrefix(relPath, string(os.PathSeparator)) ||
		strings.HasPrefix(relPath, "/") {
		return "", fmt.Errorf("%q: must be a relative path", relPath)
	}

	absFilePath, err := filepath.Abs(filepath.Join(absBase, relPath))
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(absBase, absFilePath)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%q: path escapes base directory %q", relPath, baseDir)
	}

	return absFilePath, nil
}
