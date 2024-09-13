//go:build freebsd

package types

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func GetFSType(path string) (string, error) {
	var fsStat unix.Statfs_t

	if err := unix.Statfs(path, &fsStat); err != nil {
		return "", fmt.Errorf("failed to get filesystem type: %w", err)
	}

	bs := fsStat.Fstypename

	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	return string(b), nil
}
