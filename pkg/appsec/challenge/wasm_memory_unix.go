//go:build unix

package challenge

import "syscall"

func reserveWasmMemory(size uint64) ([]byte, error) {
	return syscall.Mmap(-1, 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
}

// commitWasmMemory is a no-op: an anonymous mapping is demand-zero, so pages
// become resident as the guest touches them. Windows needs the explicit step.
func commitWasmMemory(_ []byte, _ uint64) error {
	return nil
}

func releaseWasmMemory(res []byte) error {
	return syscall.Munmap(res)
}
