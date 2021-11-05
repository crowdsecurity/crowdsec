package csplugin

import (
	"fmt"
	"io/fs"
	"syscall"
)

func CheckOwner(details fs.FileInfo, path string) error {
	stat := details.Sys().(*syscall.Stat_t)
	if stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("plugin at %s is not owned by root user and group", path)
	} else {
		return nil
	}
}

func CheckCredential(uid int, gid int) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
}
