//go:build !windows

package tail

import "os"

// openSharedRead opens filename so another process can still append.
func openSharedRead(filename string) (*os.File, error) {
	return os.Open(filename)
}
