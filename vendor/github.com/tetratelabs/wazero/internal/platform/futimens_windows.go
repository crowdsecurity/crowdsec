package platform

import (
	"syscall"
	"time"
)

// Define values even if not used except as sentinels.
const (
	_UTIME_NOW              = -1
	_UTIME_OMIT             = -2
	SupportsSymlinkNoFollow = false
)

func utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	return utimensPortable(path, times, symlinkFollow)
}

func futimens(fd uintptr, times *[2]syscall.Timespec) error {
	// Before Go 1.20, ERROR_INVALID_HANDLE was returned for too many reasons.
	// Kick out so that callers can use path-based operations instead.
	if !IsGo120 {
		return syscall.ENOSYS
	}

	// Per docs, zero isn't a valid timestamp as it cannot be differentiated
	// from nil. In both cases, it is a marker like syscall.UTIME_OMIT.
	// See https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
	a, w := timespecToFiletime(times)

	if a == nil && w == nil {
		return nil // both omitted, so nothing to change
	}

	// Attempt to get the stat by handle, which works for normal files
	h := syscall.Handle(fd)

	// Note: This returns ERROR_ACCESS_DENIED when the input is a directory.
	return syscall.SetFileTime(h, nil, a, w)
}

func timespecToFiletime(times *[2]syscall.Timespec) (a, w *syscall.Filetime) {
	// Handle when both inputs are current system time.
	if times == nil || times[0].Nsec == UTIME_NOW && times[1].Nsec == UTIME_NOW {
		now := time.Now().UnixNano()
		ft := syscall.NsecToFiletime(now)
		return &ft, &ft
	}

	// Now, either one of the inputs is current time, or neither. This
	// means we don't have a risk of re-reading the clock.
	a = timespecToFileTime(times, 0)
	w = timespecToFileTime(times, 1)
	return
}

func timespecToFileTime(times *[2]syscall.Timespec, i int) *syscall.Filetime {
	if times[i].Nsec == UTIME_OMIT {
		return nil
	}

	var nsec int64
	if times[i].Nsec == UTIME_NOW {
		nsec = time.Now().UnixNano()
	} else {
		nsec = syscall.TimespecToNsec(times[i])
	}
	ft := syscall.NsecToFiletime(nsec)
	return &ft
}
