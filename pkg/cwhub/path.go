package cwhub

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func isYAMLFileName(path string) bool {
	return strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")
}

// resolveSymlink returns the ultimate target path of a symlink
// returns error if the symlink is dangling or too many symlinks are followed
func resolveSymlink(pth string) (string, error) {
	const maxSymlinks = 10 // Prevent infinite loops
	cur := pth
	for range maxSymlinks {
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", err // dangling link
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			// found the target
			return cur, nil
		}

		target, err := os.Readlink(cur)
		if err != nil {
			return "", err
		}

		// relative to the link's directory?
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = target
	}

	return "", errors.New("too many levels of symbolic links")
}

// isPathInside checks if a path is inside the given directory
func isPathInside(path, dir string) (bool, error) {
	absFile, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	rel, err := filepath.Rel(absDir, absFile)
	if err != nil {
		return false, err
	}

	return !strings.HasPrefix(rel, ".."), nil
}
