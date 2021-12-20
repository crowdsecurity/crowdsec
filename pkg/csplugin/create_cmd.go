// +build linux
package csplugin

import (
	"os/exec"

	"github.com/pkg/errors"
)

func (pb *PluginBroker) CreateCmd(binaryPath string) (cmdr *exec.Cmd, err error) {
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr, err = getProcessAtr(pb.pluginProcConfig.User, pb.pluginProcConfig.Group)
	cmd.SysProcAttr.Credential.NoSetGroups = true
	if err != nil {
		return nil, errors.Wrap(err, "while getting process attributes")
	}
	return cmdr, err
}
