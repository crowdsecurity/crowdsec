package database

import (
	"fmt"
	"io/fs"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

func setFilePerm(path string, mode fs.FileMode) error {
	// On windows, we don't care about the mode, just make sure the file is only readable/writable by the owner and group

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("while getting security info: %w", err)
	}

	currentOwner, defaulted, err := sd.Owner()

	if err != nil {
		return fmt.Errorf("while getting owner: %w", err)
	}

	log.Debugf("current owner is %s (%v) (defaulted: %v)", currentOwner.String(), currentOwner, defaulted)

	currentGroup, defaulted, err := sd.Group()

	if err != nil {
		return fmt.Errorf("while getting group: %w", err)
	}

	if currentGroup == nil {
		log.Debugf("current group is nil (defaulted: %v), using builtin admin instead", defaulted)
		currentGroup, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			return fmt.Errorf("while creating admin SID: %w", err)
		}
	}

	log.Debugf("current group is %s (%v) (defaulted: %v)", currentGroup.String(), currentGroup, defaulted)

	dacl, err := windows.ACLFromEntries(
		[]windows.EXPLICIT_ACCESS{
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.NO_INHERITANCE,
				Trustee: windows.TRUSTEE{
					MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
					TrusteeForm:              windows.TRUSTEE_IS_SID,
					TrusteeType:              windows.TRUSTEE_IS_USER,
					TrusteeValue:             windows.TrusteeValueFromSID(currentOwner),
				},
			},
			{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.NO_INHERITANCE,
				Trustee: windows.TRUSTEE{
					MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
					TrusteeForm:              windows.TRUSTEE_IS_SID,
					TrusteeType:              windows.TRUSTEE_IS_GROUP,
					TrusteeValue:             windows.TrusteeValueFromSID(currentGroup),
				},
			},
		}, nil)

	if err != nil {
		return fmt.Errorf("while creating ACL: %w", err)
	}

	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)

	if err != nil {
		return fmt.Errorf("while setting security info: %w", err)
	}
	return nil
}
