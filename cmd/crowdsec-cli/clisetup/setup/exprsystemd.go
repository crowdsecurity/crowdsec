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

// UnitEnabled returns true if the unit exists and is enabled in the systemctl output.
func (e *ExprSystemd) UnitEnabled(ctx context.Context, unitName string) (bool, error) {
	e.unitsSearched[unitName] = struct{}{}
	_, ok := e.installedUnits[unitName]

	return ok, nil
}
