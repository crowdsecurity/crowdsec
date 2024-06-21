//go:build windows

package csplugin

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

var (
	advapi32 = windows.NewLazyDLL("advapi32.dll")

	procGetAce = advapi32.NewProc("GetAce")
)

type AclSizeInformation struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

type Acl struct {
	AclRevision uint8
	Sbz1        uint8
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type AccessAllowedAce struct {
	AceType    uint8
	AceFlags   uint8
	AceSize    uint16
	AccessMask uint32
	SidStart   uint32
}

const ACCESS_ALLOWED_ACE_TYPE = 0
const ACCESS_DENIED_ACE_TYPE = 1

func CheckPerms(path string) error {
	log.Debugf("checking permissions of %s\n", path)

	systemSid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinLocalSystemSid))
	if err != nil {
		return fmt.Errorf("while creating SYSTEM well known sid: %w", err)
	}

	adminSid, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinBuiltinAdministratorsSid))
	if err != nil {
		return fmt.Errorf("while creating built-in Administrators well known sid: %w", err)
	}

	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("while getting current user: %w", err)
	}

	currentUserSid, _, _, err := windows.LookupSID("", currentUser.Username)

	if err != nil {
		return fmt.Errorf("while looking up current user sid: %w", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("while getting owner security info: %w", err)
	}
	if !sd.IsValid() {
		return fmt.Errorf("security descriptor is invalid")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("while getting owner: %w", err)
	}
	if !owner.IsValid() {
		return fmt.Errorf("owner is invalid")
	}

	if !owner.Equals(systemSid) && !owner.Equals(currentUserSid) && !owner.Equals(adminSid) {
		return fmt.Errorf("plugin at %s is not owned by SYSTEM, Administrators or by current user, but by %s", path, owner.String())
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("while getting DACL: %w", err)
	}

	if dacl == nil {
		return fmt.Errorf("no DACL found on plugin, meaning fully permissive access on plugin %s", path)
	}

	rs := reflect.ValueOf(dacl).Elem()

	/*
			For reference, the structure of the ACL type is:
			type ACL struct {
			aclRevision byte
			sbz1        byte
			aclSize     uint16
			aceCount    uint16
			sbz2        uint16
		}
		As the field are not exported, we have to use reflection to access them, this should not be an issue as the structure won't (probably) change any time soon.
	*/
	aceCount := rs.Field(3).Uint()

	for i := uint64(0); i < aceCount; i++ {
		ace := &AccessAllowedAce{}
		ret, _, _ := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ret == 0 {
			return fmt.Errorf("while getting ACE: %w", windows.GetLastError())
		}
		log.Debugf("ACE %d: %+v\n", i, ace)

		if ace.AceType == ACCESS_DENIED_ACE_TYPE {
			continue
		}
		aceSid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))

		if aceSid.Equals(systemSid) || aceSid.Equals(adminSid) {
			log.Debugf("Not checking permission for well-known SID %s", aceSid.String())
			continue
		}

		if aceSid.Equals(currentUserSid) {
			log.Debugf("Not checking permission for current user %s", currentUser.Username)
			continue
		}

		log.Debugf("Checking permission for SID %s", aceSid.String())
		denyMask := ^(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
		if ace.AccessMask&uint32(denyMask) != 0 {
			return fmt.Errorf("only SYSTEM, Administrators or the user currently running crowdsec can have more than read/execute on plugin %s", path)
		}
	}

	return nil
}

func getProcessAtr() (*windows.SysProcAttr, error) {
	var procToken, token windows.Token

	proc := windows.CurrentProcess()
	defer windows.CloseHandle(proc)

	err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|
		windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_GROUPS|windows.TOKEN_ADJUST_PRIVILEGES, &procToken)
	if err != nil {
		return nil, fmt.Errorf("while opening process token: %w", err)
	}
	defer procToken.Close()

	err = windows.DuplicateTokenEx(procToken, 0, nil, windows.SecurityImpersonation,
		windows.TokenPrimary, &token)
	if err != nil {
		return nil, fmt.Errorf("while duplicating token: %w", err)
	}

	//Remove all privileges from the token

	err = windows.AdjustTokenPrivileges(token, true, nil, 0, nil, nil)

	if err != nil {
		return nil, fmt.Errorf("while adjusting token privileges: %w", err)
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
		return nil, fmt.Errorf("while setting token information: %w", err)
	}

	return &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
		Token:         syscall.Token(token),
	}, nil
}

func (pb *PluginBroker) CreateCmd(binaryPath string) (*exec.Cmd, error) {
	var err error
	cmd := exec.Command(binaryPath)
	cmd.SysProcAttr, err = getProcessAtr()
	if err != nil {
		return nil, fmt.Errorf("while getting process attributes: %w", err)
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

func pluginIsValid(path string) error {
	var err error

	// check if it exists
	if _, err = os.Stat(path); err != nil {
		return fmt.Errorf("plugin at %s does not exist", path)
	}

	// check if it is owned by root
	err = CheckPerms(path)
	if err != nil {
		return err
	}

	return nil
}
