package csnet

import (
	"fmt"
	"runtime"
)

// WrapSockErr wraps the provided error with a possible cause if the unix socket path exceeds
// a system-specific maximum length. It returns the original error otherwise.
func WrapSockErr(err error, socket string) error {
	limit := 0
	switch runtime.GOOS {
	case "linux":
		// the actual numbers are not exported in Go, so we hardcode them
		limit = 108
	case "freebsd", "darwin", "openbsd":
		limit = 104
	}
	if limit > 0 && len(socket) > limit {
		return fmt.Errorf("%w (path length exceeds system limit: %d > %d)", err, len(socket), limit)
	}
	return err
}
