// +build windows

package csplugin

import (
	"io/fs"
	"syscall"
)

func CheckOwner(details fs.FileInfo, path string) error {
	return nil
}

func CheckCredential(uid int, gid int) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
