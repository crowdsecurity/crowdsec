package osinfo

import (
	"fmt"
	"os/exec"
	"strings"
)

func readCommandOutput(cmd string, arg ...string) (result string, err error) {
	command := exec.Command(cmd, arg...)
	var bytes []byte
	bytes, err = command.CombinedOutput()
	if err == nil {
		result = strings.TrimSpace(string(bytes))
	} else {
		if len(bytes) > 0 && err.Error() == "exit status 1" {
			err = fmt.Errorf("%v", string(bytes))
		}
	}

	return
}
