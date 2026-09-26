//go:build windows

package tail

import (
	"os"

	"golang.org/x/sys/windows"
)

// openSharedRead opens filename so another process can still append, rename, or delete it.
func openSharedRead(filename string) (*os.File, error) {
	utf16Path, err := windows.UTF16PtrFromString(filename)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filename, Err: err}
	}

	handle, err := windows.CreateFile(
		utf16Path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filename, Err: err}
	}

	return os.NewFile(uintptr(handle), filename), nil
}
