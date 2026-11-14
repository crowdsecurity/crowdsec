//go:build windows

package challenge

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// reserveWasmMemory reserves address space without committing it, so the
// reservation costs neither memory nor commit charge until the guest grows into
// it — the counterpart of a lazily faulted anonymous mapping.
func reserveWasmMemory(size uint64) ([]byte, error) {
	base, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil, err
	}

	// `go vet` flags the uintptr->Pointer conversion; it is safe here because
	// the region lives outside the Go heap, so the GC neither moves nor tracks
	// it. Same pattern as wazero's own VirtualAlloc code.
	return unsafe.Slice((*byte)(unsafe.Pointer(base)), size), nil
}

// commitWasmMemory commits the reservation up to size. Committing a range that
// is already partly committed is explicitly supported and leaves those pages
// untouched, so this can run on every grow without tracking what it did before —
// and without disturbing what the guest already wrote. Newly committed pages
// are zeroed by the OS.
func commitWasmMemory(res []byte, size uint64) error {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(res)))

	_, err := windows.VirtualAlloc(base, uintptr(size), windows.MEM_COMMIT, windows.PAGE_READWRITE)

	return err
}

func releaseWasmMemory(res []byte) error {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(res)))

	// MEM_RELEASE frees the whole reservation, and requires a zero size.
	return windows.VirtualFree(base, 0, windows.MEM_RELEASE)
}
