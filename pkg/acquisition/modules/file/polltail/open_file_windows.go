//go:build windows

package polltail

import (
	"os"

	"golang.org/x/sys/windows"
)

// openSharedRead opens filename for reading and still lets another process append, rename, or delete it.
func openSharedRead(filename string) (*os.File, error) {
	utf16Path, err := windows.UTF16PtrFromString(filename)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filename, Err: err}
	}

	// Same CreateFile shape as github.com/nxadm/tail v1.4.11 winfile.Open for a read-only existing file.
	// GENERIC_READ is read-only access.
	// FILE_SHARE_READ lets other readers open the file. FILE_SHARE_WRITE lets the logger append.
	// FILE_SHARE_DELETE lets a rotator rename or remove the file during this read.
	// os.Open shares read and write only, so a rotator could not rename the file during that read.
	// nil security attributes, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, and a zero template match that nxadm open.
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
