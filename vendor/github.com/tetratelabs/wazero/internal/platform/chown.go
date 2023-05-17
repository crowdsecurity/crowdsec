package platform

import (
	"io/fs"
	"os"
	"syscall"
)

// Chown is like os.Chown, except it returns a syscall.Errno, not a
// fs.PathError. For example, this returns syscall.ENOENT if the path doesn't
// exist. See https://linux.die.net/man/3/chown
//
// Note: This always returns syscall.ENOSYS on windows.
func Chown(path string, uid, gid int) error {
	err := os.Chown(path, uid, gid)
	return UnwrapOSError(err)
}

// Lchown is like os.Lchown, except it returns a syscall.Errno, not a
// fs.PathError. For example, this returns syscall.ENOENT if the path doesn't
// exist. See https://linux.die.net/man/3/lchown
//
// Note: This always returns syscall.ENOSYS on windows.
func Lchown(path string, uid, gid int) error {
	err := os.Lchown(path, uid, gid)
	return UnwrapOSError(err)
}

// ChownFile is like syscall.Fchown, but for nanosecond precision and
// fs.File instead of a file descriptor. This returns syscall.EBADF if the file
// or directory was closed. See https://linux.die.net/man/3/fchown
//
// Note: This always returns syscall.ENOSYS on windows.
func ChownFile(f fs.File, uid, gid int) error {
	if f, ok := f.(fdFile); ok {
		err := fchown(f.Fd(), uid, gid)
		return UnwrapOSError(err)
	}
	return syscall.ENOSYS
}
