package setup

import (
	"context"
)

type ExprSystemd struct {
	installedUnits UnitMap
	unitsSearched  UnitMap
}

func NewExprSystemd(installedUnits UnitMap) *ExprSystemd {
	ret := &ExprSystemd{
		installedUnits: installedUnits,
		unitsSearched:  make(UnitMap),
	}

	return ret
}

// UnitInstalled returns true if the unit is found in the systemctl output.
func (e *ExprSystemd) UnitInstalled(ctx context.Context, unitName string) (bool, error) {
	e.unitsSearched[unitName] = struct{}{}
	_, ok := e.installedUnits[unitName]

	return ok, nil
}
