//go:build freebsd

package fsutil

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func GetFSType(path string) (string, error) {
	var fsStat unix.Statfs_t

	if err := unix.Statfs(path, &fsStat); err != nil {
		return "", fmt.Errorf("failed to get filesystem type: %w", err)
	}

	return unix.ByteSliceToString(fsStat.Fstypename[:]), nil
}
