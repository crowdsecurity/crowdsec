//go:build !windows

package platform

import "syscall"

func fchown(fd uintptr, uid, gid int) error {
	return syscall.Fchown(int(fd), uid, gid)
}
