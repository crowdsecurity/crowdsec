//go:build !windows

package tail

import "os"

// filePathGone is true when Stat failed because the path is gone.
func filePathGone(err error) bool {
	return os.IsNotExist(err)
}
