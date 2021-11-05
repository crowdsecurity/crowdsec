package fileacquisition

import (
	"golang.org/x/sys/unix"
)

func checkAccess(file string) error {
	return unix.Access(file, unix.R_OK)
}
