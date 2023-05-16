package platform

import (
	"syscall"
	"unsafe"
	_ "unsafe" // for go:linkname
)

const (
	_AT_FDCWD               = -0x64
	_AT_SYMLINK_NOFOLLOW    = 0x100
	_UTIME_NOW              = (1 << 30) - 1
	_UTIME_OMIT             = (1 << 30) - 2
	SupportsSymlinkNoFollow = true
)

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) (err error) {
	var flags int
	if !symlinkFollow {
		flags = _AT_SYMLINK_NOFOLLOW
	}

	var _p0 *byte
	_p0, err = syscall.BytePtrFromString(path)
	if err != nil {
		return
	}
	return utimensat(_AT_FDCWD, uintptr(unsafe.Pointer(_p0)), times, flags)
}

// On linux, implement futimens via utimensat with the NUL path.
func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	return utimensat(int(fd), 0 /* NUL */, times, 0)
}

// utimensat is like syscall.utimensat special-cased to accept a NUL string for the path value.
func utimensat(dirfd int, strPtr uintptr, times *[2]syscall.Timespec, flags int) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_UTIMENSAT, uintptr(dirfd), strPtr, uintptr(unsafe.Pointer(times)), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = e1
	}
	return
}
