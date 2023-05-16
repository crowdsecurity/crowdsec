//go:build windows

package platform

import "syscall"

// fchown is not supported on windows. For example, syscall.Fchown returns
// syscall.EWINDOWS, which is the same as syscall.ENOSYS.
func fchown(fd uintptr, uid, gid int) error {
	return syscall.ENOSYS
}
