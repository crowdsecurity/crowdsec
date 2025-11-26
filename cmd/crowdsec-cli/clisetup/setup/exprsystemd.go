package setup

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
)

var ErrSystemdPropertyNotFound = errors.New("systemd property not found")

type ExprSystemd struct {
	installedUnits UnitMap
	logger         logrus.FieldLogger
}

func NewExprSystemd(installedUnits UnitMap, logger logrus.FieldLogger) *ExprSystemd {
	ret := &ExprSystemd{
		installedUnits: installedUnits,
		logger:         logger,
	}

	return ret
}

// UnitInstalled returns true if the unit is installed, even if it is not enabled or running.
func (e *ExprSystemd) UnitInstalled(_ context.Context, unitName string) (bool, error) {
	_, ok := e.installedUnits[unitName]

	return ok, nil
}

// UnitConfig returns the value of the specified key in the unit's configuration.
func (e *ExprSystemd) UnitConfig(_ context.Context, unitName, key string) (string, error) {
	unit, ok := e.installedUnits[unitName]
	if !ok {
		// unit not installed
		return "", nil
	}

	val, ok := unit.Config[key]
	if !ok {
		// unit installed but key not found
		return "", ErrSystemdPropertyNotFound
	}

	return val, nil
}

// UnitLogsToJournal returns true if the unit's logs are configured to go to the journal, either through
// standard output or standard error.
func (e *ExprSystemd) UnitLogsToJournal(ctx context.Context, unitName string) (bool, error) {
	stdout, err := e.UnitConfig(ctx, unitName, "StandardOutput")
	switch {
	case errors.Is(err, ErrSystemdPropertyNotFound):
		e.logger.WithField("unit", unitName).WithField("key", "StandardOutput").Error(err)
		return false, nil
	case err != nil:
		return false, err
	}

	if stdout == "journal" || stdout == "journal+console" {
		return true, nil
	}

	stderr, err := e.UnitConfig(ctx, unitName, "StandardError")
	switch {
	case errors.Is(err, ErrSystemdPropertyNotFound):
		e.logger.WithField("unit", unitName).WithField("key", "StandardError").Error(err)
		return false, nil
	case err != nil:
		return false, err
	}

	if stderr == "journal" || stderr == "journal+console" {
		return true, nil
	}

	return false, nil
}
