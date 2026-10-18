//go:build !windows

package polltail

import "os"

// filePathGone is true when Stat failed because the path is gone.
func filePathGone(err error) bool {
	return os.IsNotExist(err)
}
