package fsutil

import (
	"strings"
)

func IsNetworkFS(path string) (bool, string, error) {
	fsType, err := GetFSType(path)
	if err != nil {
		return false, "", err
	}

	fsType = strings.ToLower(fsType)

	return fsType == "nfs" || fsType == "cifs" || fsType == "smb" || fsType == "smb2", fsType, nil
}
