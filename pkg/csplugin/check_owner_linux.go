package csplugin

import (
	"fmt"
	"io/fs"
	"syscall"
)

func CheckOwner(details fs.FileInfo, path string) error {
	// check if it is owned by current user
	currentUser, err := user.Current()
	if err != nil {
		return errors.Wrap(err, "while getting current user")
	}
	procAttr, err := getProcessAtr(currentUser.Username, currentUser.Username)
	if err != nil {
		return errors.Wrap(err, "while getting process attributes")
	}
	stat := details.Sys().(*syscall.Stat_t)
	if stat.Uid != procAttr.Credential.Uid || stat.Gid != procAttr.Credential.Gid {
		return fmt.Errorf("plugin at %s is not owned by %s user and group", path, currentUser.Username)
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
