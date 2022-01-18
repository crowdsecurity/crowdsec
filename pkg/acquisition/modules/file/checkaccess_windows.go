//go:build windows
// +build windows

package fileacquisition

import (
	"os"
)

func checkAccess(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}
