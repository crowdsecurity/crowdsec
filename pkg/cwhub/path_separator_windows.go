package cwhub

import (
	"path/filepath"
	"strings"
)

func CheckSuffix(hubpath string, remotePath string) bool {
	newPath := filepath.ToSlash(hubpath)
	if !strings.HasSuffix(newPath, remotePath) {
		return true
	} else {
		return false
	}
}

func CheckName(vname string, fauthor string, fname string) bool {
	//if vname+".yaml" != fauthor+"/"+fname {
	//	return true
	//} else {
	return false
	//}
}
