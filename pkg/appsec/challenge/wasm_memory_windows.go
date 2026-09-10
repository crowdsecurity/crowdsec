//go:build windows

package challenge

import "errors"

// Windows has no equivalent one-liner for a lazily-committed anonymous
// reservation we can hand out as a Go slice, so it uses the heap fallback.
func reserveWasmMemory(_ uint64) ([]byte, error) {
	return nil, errors.New("anonymous memory mapping is not implemented on windows")
}

func releaseWasmMemory(_ []byte) error {
	return nil
}
