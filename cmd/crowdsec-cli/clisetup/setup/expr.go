package setup

import (
	"context"
	"fmt"

	"github.com/Masterminds/semver/v3"
	log "github.com/sirupsen/logrus"
)

// ExprState keeps a global state for the duration of the service detection (cache etc.)
type ExprState struct {
	unitsSearched map[string]bool
	detectOptions DetectOptions

	// cache
	installedUnits map[string]bool
	// true if the list of running processes has already been retrieved, we can
	// avoid getting it a second time.
	processesSearched map[string]bool
	// cache
	runningProcesses map[string]bool
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

type UnitLister interface {
    ListUnits(ctx context.Context) ([]string, error)
}

type ProcessLister interface {
    ListProcesses(ctx context.Context) ([]string, error)
}

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS ExprOS
	Ctx context.Context //nolint:containedctx
	_state        ExprState

	PathChecker   PathChecker
	UnitLister    UnitLister
	ProcessLister ProcessLister
}

// NewExprEnvironment creates an environment object for the rule engine.
func NewExprEnvironment(ctx context.Context, opts DetectOptions, os ExprOS, pathChecker PathChecker, unitLister UnitLister, processLister ProcessLister) *ExprEnvironment {
	return &ExprEnvironment{
		_state: ExprState{
			detectOptions: opts,

			unitsSearched:  make(map[string]bool),
			installedUnits: make(map[string]bool),

			processesSearched: make(map[string]bool),
			runningProcesses:  make(map[string]bool),
		},
		OS:            os,
		Ctx: ctx,

		PathChecker: pathChecker,
		UnitLister: unitLister,
		ProcessLister: processLister,
	}
}

// PathExists returns true if the given path exists.
func (e *ExprEnvironment) PathExists(ctx context.Context, path string) bool {
	return e.PathChecker.Exists(path)
}

func (e *ExprEnvironment) loadUnits(ctx context.Context) error {
	if len(e._state.unitsSearched) != 0 {
		return nil
	}

	for _, name := range e._state.detectOptions.ForcedUnits {
		e._state.installedUnits[name] = true
	}

	if e._state.detectOptions.SkipSystemd {
		return nil
	}

	log.Debugf("Running systemctl...")

	units, err := e.UnitLister.ListUnits(ctx)
	if err != nil {
		return err
	}

	for _, name := range units {
		e._state.installedUnits[name] = true
	}

	return nil
}

// UnitFound returns true if the unit is listed in the systemctl output.
// Whether a disabled or failed unit is considered found or not, depends on the
// systemctl parameters used.
func (e *ExprEnvironment) UnitFound(ctx context.Context, unitName string) (bool, error) {
	if err := e.loadUnits(ctx); err != nil {
		return false, err
	}

	e._state.unitsSearched[unitName] = true

	if e._state.installedUnits[unitName] {
		return true, nil
	}

	return false, nil
}

func (e *ExprEnvironment) loadProcesses(ctx context.Context) error {
	if len(e._state.processesSearched) != 0 {
		return nil
	}

	for _, name := range e._state.detectOptions.ForcedProcesses {
		e._state.runningProcesses[name] = true
	}

	procNames, err := e.ProcessLister.ListProcesses(ctx)
	if err != nil {
		return fmt.Errorf("while listing running processes: %w", err)
	}

	for _, name := range procNames {
		e._state.runningProcesses[name] = true
	}

	return nil
}

// ProcessRunning returns true if there is a running process with the given name.
func (e *ExprEnvironment) ProcessRunning(ctx context.Context, processName string) (bool, error) {
	if err := e.loadProcesses(ctx); err != nil {
		return false, err
	}

	e._state.processesSearched[processName] = true

	return e._state.runningProcesses[processName], nil
}

// return units that have been forced but not searched yet.
func (e *ExprEnvironment) unsearchedUnits() []string {
	ret := []string{}

	for _, unit := range e._state.detectOptions.ForcedUnits {
		if !e._state.unitsSearched[unit] {
			ret = append(ret, unit)
		}
	}

	return ret
}

// return processes that have been forced but not searched yet.
func (e *ExprEnvironment) unsearchedProcesses() []string {
	ret := []string{}

	for _, proc := range e._state.detectOptions.ForcedProcesses {
		if !e._state.processesSearched[proc] {
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
