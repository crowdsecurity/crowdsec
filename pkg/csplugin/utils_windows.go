//go:build windows

package csplugin

import (
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

func CheckOwner(details fs.FileInfo, path string) error {
	spew.Dump(details)
	return nil
}

func getProcessAtr() (*syscall.SysProcAttr, error) {
	var procToken, token windows.Token

	proc := windows.CurrentProcess()
	defer windows.CloseHandle(proc)

	err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|
		windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_GROUPS|windows.TOKEN_ADJUST_PRIVILEGES, &procToken)
	if err != nil {
		return nil, errors.Wrapf(err, "while opening process token")
	}
	defer procToken.Close()

	err = windows.DuplicateTokenEx(procToken, 0, nil, windows.SecurityImpersonation,
		windows.TokenPrimary, &token)
	if err != nil {
		return nil, errors.Wrapf(err, "while duplicating token")
	}

	//Remove all privileges from the token

	err = windows.AdjustTokenPrivileges(token, true, nil, 0, nil, nil)

	if err != nil {
		return nil, errors.Wrapf(err, "while adjusting token privileges")
	}

	//Run the plugin as a medium integrity level process
	//For some reasons, low level integrity don't work, the plugin and crowdsec cannot communicate over the TCP socket
	sid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinMediumLabelSid))
	if err != nil {
		return nil, err
	}

	tml := &windows.Tokenmandatorylabel{}
	tml.Label.Attributes = windows.SE_GROUP_INTEGRITY
	tml.Label.Sid = sid

	err = windows.SetTokenInformation(token, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(tml)), tml.Size())
	if err != nil {
		token.Close()
		return nil, errors.Wrapf(err, "while setting token information")
	}

	return &windows.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		Token:         syscall.Token(token),
	}, nil
}

func (pb *PluginBroker) CreateCmd(binaryPath string) (*exec.Cmd, error) {
	var err error
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr, err = getProcessAtr()
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
