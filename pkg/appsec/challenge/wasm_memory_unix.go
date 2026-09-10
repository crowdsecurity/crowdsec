//go:build unix

package challenge

import "syscall"

func reserveWasmMemory(size uint64) ([]byte, error) {
	return syscall.Mmap(-1, 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
}

func releaseWasmMemory(res []byte) error {
	return syscall.Munmap(res)
}
