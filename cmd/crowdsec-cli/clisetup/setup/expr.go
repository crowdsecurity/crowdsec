package setup

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// ExprState keeps a global state for the duration of the service detection (cache etc.)
type ExprState struct {
	detectOptions DetectOptions

	installedUnits UnitMap
	unitsSearched UnitMap

	runningProcesses ProcessMap
	processesSearched ProcessMap
}

func NewExprState(opts DetectOptions, installedunits UnitMap, runningProcesses ProcessMap) *ExprState {
	return &ExprState{
		detectOptions: opts,

		installedUnits:  installedunits,
		unitsSearched:   make(UnitMap),

		runningProcesses:  runningProcesses,
		processesSearched: make(ProcessMap),
	}
}

// ExprOS contains the detected (or forced) OS fields available to the rule engine.
type ExprOS struct {
	Family     string
	ID         string
	RawVersion string
}

// VersionCheck returns true if the version of the OS matches the given constraint
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

// VersionAtLeast returns true if the version of the OS is at least the given version.
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

type PathChecker interface {
    Exists(path string) bool
}

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS ExprOS
	Ctx context.Context //nolint:containedctx
	_state        *ExprState

	PathChecker   PathChecker
}

// NewExprEnvironment creates an environment object for the rule engine.
func NewExprEnvironment(ctx context.Context, os ExprOS, state *ExprState, pathChecker PathChecker) *ExprEnvironment {
	return &ExprEnvironment{
		Ctx: ctx,
		OS:            os,
		_state: state,
		PathChecker: pathChecker,
	}
}

// PathExists returns true if the given path exists.
func (e *ExprEnvironment) PathExists(ctx context.Context, path string) bool {
	return e.PathChecker.Exists(path)
}

// UnitFound returns true if the unit is listed in the systemctl output.
// Whether a disabled or failed unit is considered found or not, depends on the
// systemctl parameters used.
func (e *ExprEnvironment) UnitFound(ctx context.Context, unitName string) (bool, error) {
	e._state.unitsSearched[unitName] = struct{}{}
	_, ok := e._state.installedUnits[unitName]
	return ok, nil
}

// ProcessRunning returns true if there is a running process with the given name.
func (e *ExprEnvironment) ProcessRunning(ctx context.Context, processName string) (bool, error) {
	e._state.processesSearched[processName] = struct{}{}
	_, ok := e._state.runningProcesses[processName]
	return ok, nil
}

// return units that have been forced but not searched yet.
func (e *ExprEnvironment) unsearchedUnits() []string {
	ret := []string{}

	for _, unit := range e._state.detectOptions.ForcedUnits {
		if _, ok := e._state.unitsSearched[unit]; !ok {
			ret = append(ret, unit)
		}
	}

	return ret
}

// return processes that have been forced but not searched yet.
func (e *ExprEnvironment) unsearchedProcesses() []string {
	ret := []string{}

	for _, proc := range e._state.detectOptions.ForcedProcesses {
		if _, ok := e._state.processesSearched[proc]; !ok {
			ret = append(ret, proc)
		}
	}

	return ret
}

// checkConsumedForcedItems checks if all the "forced" options (units or processes) have been evaluated during the service detection.
func checkConsumedForcedItems(e *ExprEnvironment) error {
	unconsumed := e.unsearchedUnits()

	unitMsg := ""
	if len(unconsumed) > 0 {
		unitMsg = fmt.Sprintf("unit(s) required but not supported: %v", unconsumed)
	}

	unconsumed = e.unsearchedProcesses()

	procsMsg := ""
	if len(unconsumed) > 0 {
		procsMsg = fmt.Sprintf("process(es) required but not supported: %v", unconsumed)
	}

	join := ""
	if unitMsg != "" && procsMsg != "" {
		join = "; "
	}

	if unitMsg != "" || procsMsg != "" {
		return fmt.Errorf("%s%s%s", unitMsg, join, procsMsg)
	}

	return nil
}
