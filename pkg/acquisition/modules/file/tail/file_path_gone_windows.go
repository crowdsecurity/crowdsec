//go:build windows

package tail

import "os"

// filePathGone is true when Stat failed because the path is gone.
// Windows reports access denied while a rotator deletes a locked file.
func filePathGone(err error) bool {
	return os.IsNotExist(err) || os.IsPermission(err)
}
