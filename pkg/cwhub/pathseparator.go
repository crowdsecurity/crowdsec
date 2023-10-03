//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package cwhub

import "strings"

func hasPathSuffix(hubpath string, remotePath string) bool {
	return strings.HasSuffix(hubpath, remotePath)
}
