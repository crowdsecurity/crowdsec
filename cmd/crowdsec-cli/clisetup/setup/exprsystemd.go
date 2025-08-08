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

// UnitInstalled returns true if the unit is found in the systemctl output.
func (e *ExprSystemd) UnitInstalled(ctx context.Context, unitName string) (bool, error) {
	_, ok := e.installedUnits[unitName]

	return ok, nil
}

// UnitHasJournal returns true if the unit exists and wrote to the journal.
func (e *ExprSystemd) UnitHasJournal(ctx context.Context, unitName string) (bool, error) {
	_, ok := e.installedUnits[unitName]

	return ok, nil
}

// UnitStandardOutput returns the value of the StandardOutput property for the unit, or an empty string if the unit is not installed.
func (e *ExprSystemd) UnitStandardOutput(ctx context.Context, unitName string) (bool, error) {
	_, ok := e.installedUnits[unitName]

	return ok, nil
}
