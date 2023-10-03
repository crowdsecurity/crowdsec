package cwhub

import (
	"path/filepath"
	"strings"
)

func hasPathSuffix(hubpath string, remotePath string) bool {
	newPath := filepath.ToSlash(hubpath)
	return strings.HasSuffix(newPath, remotePath)
}
