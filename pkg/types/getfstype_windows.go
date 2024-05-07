package types

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

func GetFSType(path string) (string, error) {
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return "", err
	}
	defer syscall.FreeLibrary(kernel32)

	getVolumeInformation, err := syscall.GetProcAddress(kernel32, "GetVolumeInformationW")
	if err != nil {
		return "", err
	}

	// Convert relative path to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	// Get the root path of the volume
	volumeRoot := filepath.VolumeName(absPath) + "\\"

	volumeRootPtr, _ := syscall.UTF16PtrFromString(volumeRoot)

	var (
		fileSystemNameBuffer = make([]uint16, 260)
		nFileSystemNameSize  = uint32(len(fileSystemNameBuffer))
	)

	ret, _, err := syscall.SyscallN(getVolumeInformation,
		uintptr(unsafe.Pointer(volumeRootPtr)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&fileSystemNameBuffer[0])),
		uintptr(nFileSystemNameSize),
		0)

	if ret == 0 {
		return "", err
	}

	return syscall.UTF16ToString(fileSystemNameBuffer), nil
}
