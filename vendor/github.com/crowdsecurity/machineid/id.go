// Package machineid provides support for reading the unique machine id of most OSs (without admin privileges).
//
// https://github.com/denisbrodbeck/machineid
//
// https://godoc.org/github.com/denisbrodbeck/machineid/cmd/machineid
//
// This package is Cross-Platform (tested on Win7+, Debian 8+, Ubuntu 14.04+, OS X 10.6+, FreeBSD 11+)
// and does not use any internal hardware IDs (no MAC, BIOS, or CPU).
//
// Returned machine IDs are generally stable for the OS installation
// and usually stay the same after updates or hardware changes.
//
// This package allows sharing of machine IDs in a secure way by
// calculating HMAC-SHA256 over a user provided app ID, which is keyed by the machine id.
//
// Caveat: Image-based environments have usually the same machine-id (perfect clone).
// Linux users can generate a new id with `dbus-uuidgen` and put the id into
// `/var/lib/dbus/machine-id` and `/etc/machine-id`.
// Windows users can use the `sysprep` toolchain to create images, which produce valid images ready for distribution.
package machineid // import "github.com/denisbrodbeck/machineid"

import (
	"fmt"
)

// ID returns the platform specific machine id of the current host OS.
// Regard the returned id as "confidential" and consider using ProtectedID() instead.
func ID() (string, error) {
	id, err := machineID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}
	return id, nil
}

// ProtectedID returns a hashed version of the machine ID in a cryptographically secure way,
// using a fixed, application-specific key.
// Internally, this function calculates HMAC-SHA256 of the application ID, keyed by the machine ID.
func ProtectedID(appID string) (string, error) {
	id, err := ID()
	if err != nil {
		return "", fmt.Errorf("machineid: %v", err)
	}
	return protect(appID, id), nil
}
