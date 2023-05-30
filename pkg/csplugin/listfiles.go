package csplugin

import (
	"os"
	"path/filepath"
)

// helper which gives paths to all files in the given directory non-recursively
func listFilesAtPath(path string) ([]string, error) {
	filePaths := make([]string, 0)
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if ! file.IsDir() {
			filePaths = append(filePaths, filepath.Join(path, file.Name()))
		}
	}
	return filePaths, nil
}

