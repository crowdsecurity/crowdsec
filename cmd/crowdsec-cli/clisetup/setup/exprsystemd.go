package setup

import (
	"context"

	"github.com/sirupsen/logrus"
)

type ExprSystemd struct{
	forcedUnits UnitMap		// slice of unit names that we want to force-detect.
	installedUnits UnitMap
	unitsSearched  UnitMap
}

func NewExprSystemd(installedUnits UnitMap, forcedUnits []string) *ExprSystemd {
	ret := &ExprSystemd{
		installedUnits: installedUnits,
		unitsSearched:  make(UnitMap),
	}
	ret.forcedUnits = make(UnitMap, len(forcedUnits))
	for _, unit := range forcedUnits {
		ret.forcedUnits[unit] = struct{}{}
	}
	return ret
}

// UnitEnabled returns true if the unit exists and is enabled in the systemctl output.
func (e *ExprSystemd) UnitEnabled(ctx context.Context, unitName string) (bool, error) {
	e.unitsSearched[unitName] = struct{}{}
	_, ok := e.installedUnits[unitName]
	return ok, nil
}

// unsearchedUnits() returns units that have been forced but not searched yet.
func (e *ExprSystemd) unsearchedUnits() []string {
	ret := []string{}

	for unit := range e.forcedUnits {
		if _, ok := e.unitsSearched[unit]; !ok {
			ret = append(ret, unit)
		}
	}

	return ret
}

// checkConsumedForcedUnits checks if all the "forced" units have been evaluated during the service detection.
func (e *ExprSystemd) checkConsumedForcedUnits(logger logrus.FieldLogger) {
	unconsumed := e.unsearchedUnits()

	if len(unconsumed) > 0 {
		logger.Warnf("No service matched the following units: %v. They are likely unsupported by the detection configuration.", unconsumed)
	}
}
