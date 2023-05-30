package platform

import (
	"io/fs"
	"syscall"
	"time"
	"unsafe"
)

const (
	// UTIME_NOW is a special syscall.Timespec NSec value used to set the
	// file's timestamp to a value close to, but not greater than the current
	// system time.
	UTIME_NOW = _UTIME_NOW

	// UTIME_OMIT is a special syscall.Timespec NSec value used to avoid
	// setting the file's timestamp.
	UTIME_OMIT = _UTIME_OMIT
)

// Utimens set file access and modification times on a path resolved to the
// current working directory, at nanosecond precision.
//
// # Parameters
//
// The `times` parameter includes the access and modification timestamps to
// assign. Special syscall.Timespec NSec values UTIME_NOW and UTIME_OMIT may be
// specified instead of real timestamps. A nil `times` parameter behaves the
// same as if both were set to UTIME_NOW.
//
// When the `symlinkFollow` parameter is true and the path is a symbolic link,
// the target of expanding that link is updated.
//
// # Errors
//
// The following errors are expected:
//   - syscall.EINVAL: `path` is invalid.
//   - syscall.EEXIST: `path` exists and is a directory.
//   - syscall.ENOTDIR: `path` exists and is a file.
//
// # Notes
//
//   - This is similar to syscall.UtimesNano, except that doesn't have flags to
//     control expansion of symbolic links. It also doesn't support special
//     values UTIME_NOW or UTIME_NOW.
//   - This is like `utimensat` with `AT_FDCWD` in POSIX. See
//     https://pubs.opengroup.org/onlinepubs/9699919799/functions/futimens.html
func Utimens(path string, times *[2]syscall.Timespec, symlinkFollow bool) error {
	err := utimens(path, times, symlinkFollow)
	return UnwrapOSError(err)
}

// UtimensFile is like Utimens, except it works on a file, not a path.
//
// # Notes
//
//   - Windows requires files to be open with syscall.O_RDWR, which means you
//     cannot use this to update timestamps on a directory (syscall.EPERM).
//   - This is like the function `futimens` in POSIX. See
//     https://pubs.opengroup.org/onlinepubs/9699919799/functions/futimens.html
func UtimensFile(f fs.File, times *[2]syscall.Timespec) error {
	if f, ok := f.(fdFile); ok {
		err := futimens(f.Fd(), times)
		return UnwrapOSError(err)
	}
	return syscall.ENOSYS
}

func timesToPtr(times *[2]syscall.Timespec) unsafe.Pointer { //nolint:unused
	var _p0 unsafe.Pointer
	if times != nil {
		_p0 = unsafe.Pointer(&times[0])
	} else {
		_p0 = unsafe.Pointer(&_zero)
	}
	return _p0
}

func utimensPortable(path string, times *[2]syscall.Timespec, symlinkFollow bool) error { //nolint:unused
	if !symlinkFollow {
		return syscall.ENOSYS
	}

	// Handle when both inputs are current system time.
	if times == nil || times[0].Nsec == UTIME_NOW && times[1].Nsec == UTIME_NOW {
		ts := nowTimespec()
		return syscall.UtimesNano(path, []syscall.Timespec{ts, ts})
	}

	// When both inputs are omitted, there is nothing to change.
	if times[0].Nsec == UTIME_OMIT && times[1].Nsec == UTIME_OMIT {
		return nil
	}

	// Handle when neither input are special values
	if times[0].Nsec != UTIME_NOW && times[1].Nsec != UTIME_NOW &&
		times[0].Nsec != UTIME_OMIT && times[1].Nsec != UTIME_OMIT {
		return syscall.UtimesNano(path, times[:])
	}

	// Now, either atim or mtim is a special value, but not both.

	// Now, either one of the inputs is a special value, or neither. This means
	// we don't have a risk of re-reading the clock or re-doing stat.
	if atim, err := normalizeTimespec(path, times, 0); err != nil {
		return err
	} else if mtim, err := normalizeTimespec(path, times, 1); err != nil {
		return err
	} else {
		return syscall.UtimesNano(path, []syscall.Timespec{atim, mtim})
	}
}

func normalizeTimespec(path string, times *[2]syscall.Timespec, i int) (ts syscall.Timespec, err error) { //nolint:unused
	switch times[i].Nsec {
	case UTIME_NOW: // declined in Go per golang/go#31880.
		ts = nowTimespec()
		return
	case UTIME_OMIT:
		// UTIME_OMIT is expensive until progress is made in Go, as it requires a
		// stat to read-back the value to re-apply.
		// - https://github.com/golang/go/issues/32558.
		// - https://go-review.googlesource.com/c/go/+/219638 (unmerged)
		var st Stat_t
		if err = stat(path, &st); err != nil {
			return
		}
		switch i {
		case 0:
			ts = syscall.NsecToTimespec(st.Atim)
		case 1:
			ts = syscall.NsecToTimespec(st.Mtim)
		default:
			panic("BUG")
		}
		return
	default: // not special
		ts = times[i]
		return
	}
}

func nowTimespec() syscall.Timespec { //nolint:unused
	now := time.Now().UnixNano()
	return syscall.NsecToTimespec(now)
}
