//go:build !windows

package database

import (
	"io/fs"
	"os"
)

func setFilePerm(path string, mode fs.FileMode) error {
	return os.Chmod(path, mode)
}
