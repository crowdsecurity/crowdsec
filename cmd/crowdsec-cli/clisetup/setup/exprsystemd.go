package setup

import (
	"context"
)

type ExprSystemd struct {
	installedUnits UnitMap
}

func NewExprSystemd(installedUnits UnitMap) *ExprSystemd {
	ret := &ExprSystemd{
		installedUnits: installedUnits,
	}

	return ret
}

// UnitInstalled returns true if the unit is installed, even if it is not enabled or running.
func (e *ExprSystemd) UnitInstalled(ctx context.Context, unitName string) (bool, error) {
	_, ok := e.installedUnits[unitName]

	return ok, nil
}

// UnitConfig returns the value of the specified key in the unit's configuration.
func (e *ExprSystemd) UnitConfig(ctx context.Context, unitName, key string) (string, error) {
	unit, ok := e.installedUnits[unitName]
	if !ok {
		return "", nil
	}

	return unit.Config[key], nil
}

// UnitLogsToJournal returns true if the unit's logs are configured to go to the journal, either through
// standard output or standard error.
func (e *ExprSystemd) UnitLogsToJournal(ctx context.Context, unitName string) (bool, error) {
	stdout, err := e.UnitConfig(ctx, unitName, "StandardOutput")
	if err != nil {
		return false, err
	}

	if stdout == "journal" || stdout == "journal+console" {
		return true, nil
	}

	stderr, err := e.UnitConfig(ctx, unitName, "StandardError")
	if err != nil {
		return false, err
	}

	if stderr == "journal" || stderr == "journal+console" {
		return true, nil
	}

	return false, nil
}
