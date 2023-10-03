package cwhub

import (
	"path/filepath"
	"strings"
)

func hasPathSuffix(hubpath string, remotePath string) bool {
	newPath := filepath.ToSlash(hubpath)
	return strings.HasSuffix(newPath, remotePath)
}

func CheckName(vname string, fauthor string, fname string) bool {
	return (vname+".yaml" != fauthor+"/"+fname) && (vname+".yml" != fauthor+"/"+fname)
}
