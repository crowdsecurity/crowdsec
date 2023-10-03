//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package cwhub

import "strings"

const PathSeparator = "/"

func hasPathSuffix(hubpath string, remotePath string) bool {
	return strings.HasSuffix(hubpath, remotePath)
}

func CheckName(vname string, fauthor string, fname string) bool {
	return (vname+".yaml" != fauthor+"/"+fname) && (vname+".yml" != fauthor+"/"+fname)
}
