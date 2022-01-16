//go:build windows

package csplugin

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

func CheckOwner(details fs.FileInfo, path string) error {
	spew.Dump(details)
	return nil
}

func CheckCredential(uid string, gid string) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

func getProcessAtr(username string, groupname string) (*syscall.SysProcAttr, error) {
	if !strings.Contains(username, "\\") {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get hostname to build full username")
		}
		username = fmt.Sprintf("%s\\%s", hostname, username)
	}
	u, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}

	return CheckCredential(u.Uid, u.Gid), nil
}

func (pb *PluginBroker) CreateCmd(binaryPath string) (*exec.Cmd, error) {
	var err error
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr, err = getProcessAtr(pb.pluginProcConfig.User, pb.pluginProcConfig.Group)
	if err != nil {
		return nil, errors.Wrap(err, "while getting process attributes")
	}
	return cmd, err
}

func getPluginTypeAndSubtypeFromPath(path string) (string, string, error) {
	pluginFileName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

	parts := strings.Split(pluginFileName, "-")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("plugin name %s is invalid. Name should be like {type-name}", path)
	}
	return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1], nil
}
