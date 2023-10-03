//go:build linux || freebsd || netbsd || openbsd || solaris || !windows
// +build linux freebsd netbsd openbsd solaris !windows

package cwhub

import "strings"

const PathSeparator = "/"

func hasPathSuffix(hubpath string, remotePath string) bool {
	if strings.HasSuffix(hubpath, remotePath) {
		return true
	}
	return false
}

func CheckName(vname string, fauthor string, fname string) bool {
	if vname+".yaml" != fauthor+"/"+fname && vname+".yml" != fauthor+"/"+fname {
		return true
	} else {
		return false
	}
}
