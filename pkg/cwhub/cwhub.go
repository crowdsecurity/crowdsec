// Package cwhub is responsible for installing and upgrading the local hub files.
//
// This includes retrieving the index, the items to install (parsers, scenarios, data files...)
// and managing the dependencies and taints.
package cwhub

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

var hubClient = &http.Client{
	Timeout: 120 * time.Second,
}

// safePath returns a joined path and ensures that it does not escape the base directory.
func safePath(dir, filePath string) (string, error) {
	absBaseDir, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return "", err
	}

	absFilePath, err := filepath.Abs(filepath.Join(dir, filePath))
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(absFilePath, absBaseDir) {
		return "", fmt.Errorf("path %s escapes base directory %s", filePath, dir)
	}

	return absFilePath, nil
}
