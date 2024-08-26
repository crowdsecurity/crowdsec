//go:build openbsd

package types

import (
    "fmt"
    "syscall"
)

func GetFSType(path string) (string, error) {
	var fsStat syscall.Statfs_t

	if err := syscall.Statfs(path, &fsStat); err != nil {
		return "", fmt.Errorf("failed to get filesystem type: %w", err)
	}

	bs := fsStat.F_fstypename

	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}

	return string(b), nil
}
