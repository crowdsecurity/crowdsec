package setup

import (
	"fmt"

	"github.com/blackfireio/osinfo"
	"github.com/sirupsen/logrus"
)

func DetectOS(forcedOS ExprOS, logger *logrus.Logger) (ExprOS, error) {
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
