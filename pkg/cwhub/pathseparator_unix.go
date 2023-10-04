//go:build unix

package cwhub

import "strings"

func hasPathSuffix(hubpath string, remotePath string) bool {
	return strings.HasSuffix(hubpath, remotePath)
}
