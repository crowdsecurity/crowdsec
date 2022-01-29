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

func getProcessAtr(username string, groupname string) (*syscall.SysProcAttr, error) {
	var procToken, token windows.Token

	proc := windows.CurrentProcess()
	defer windows.CloseHandle(proc)

	err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|
		windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &procToken)
	if err != nil {
		return nil, err
	}
	defer procToken.Close()

	err = windows.DuplicateTokenEx(procToken, 0, nil, windows.SecurityImpersonation,
		windows.TokenPrimary, &token)
	if err != nil {
		return nil, err
	}

	sid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinLowLabelSid))
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
		return nil, err
	}

	return &windows.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		Token:         syscall.Token(token),
	}, nil
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
