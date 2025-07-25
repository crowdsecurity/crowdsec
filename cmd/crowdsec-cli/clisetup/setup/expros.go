package setup

import (
	"fmt"

	"github.com/blackfireio/osinfo"
	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"
)

// ExprOS contains the detected (or forced) OS fields available to the rule engine.
type ExprOS struct {
	Family     string
	ID         string
	RawVersion string
}

// VersionCheck returns true if the version of the OS matches the given constraint.
func (os ExprOS) VersionCheck(constraint string) (bool, error) {
	v, err := semver.NewVersion(os.RawVersion)
	if err != nil {
		return false, err
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}

func (os ExprOS) VersionAtLeast(constraint string) (bool, error) {
	return os.VersionCheck(">=" + constraint)
}

// VersionIsLower returns true if the version of the OS is lower than the given version.
func (os ExprOS) VersionIsLower(version string) (bool, error) {
	result, err := os.VersionAtLeast(version)
	if err != nil {
		return false, err
	}

	return !result, nil
}

func DetectOS(forcedOS ExprOS, logger logrus.FieldLogger) (ExprOS, error) {
	if forcedOS != (ExprOS{}) {
		logger.Debugf("Forced OS - %+v", forcedOS)
		return forcedOS, nil
	}

	osfull, err := osinfo.GetOSInfo()
	if err != nil {
		return ExprOS{}, fmt.Errorf("detecting OS: %w", err)
	}

	logger.Debugf("Detected OS - %+v", *osfull)

	return ExprOS{
		Family:     osfull.Family,
		ID:         osfull.ID,
		RawVersion: osfull.Version,
	}, nil
}
