//go:build linux

package csplugin

import (
	"os"
)

func getUUID() (string, error) {
	d, err := os.ReadFile("/proc/sys/kernel/random/uuid")
	if err != nil {
		return "", err
	}
	return string(d), nil
}
