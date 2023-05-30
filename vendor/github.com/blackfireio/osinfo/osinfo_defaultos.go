// +build !windows

package osinfo

import (
	"os/exec"
	"strings"
)

func readCommandOutput(cmd string, arg ...string) (result string, err error) {
	command := exec.Command(cmd, arg...)
	var bytes []byte
	bytes, err = command.CombinedOutput()
	if err == nil {
		result = strings.TrimSpace(string(bytes))
	}

	return
}
