package setup

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/Masterminds/semver/v3"
	"github.com/shirou/gopsutil/v3/process"
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

// ExprServiceState keeps a local state during the detection of a single service. It is reset before each service rules' evaluation.
type ExprServiceState struct {
	detectedUnits []string
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

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS ExprOS

	_serviceState *ExprServiceState
	_state        *ExprState
}

// NewExprEnvironment creates an environment object for the rule engine.
func NewExprEnvironment(opts DetectOptions, os ExprOS) ExprEnvironment {
	return ExprEnvironment{
		_state: &ExprState{
			detectOptions: opts,

			unitsSearched:  make(map[string]bool),
			installedUnits: make(map[string]bool),

			processesSearched: make(map[string]bool),
			runningProcesses:  make(map[string]bool),
		},
		_serviceState: &ExprServiceState{},
		OS:            os,
	}
}

// PathExists returns true if the given path exists.
func (e ExprEnvironment) PathExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// UnitFound returns true if the unit is listed in the systemctl output.
// Whether a disabled or failed unit is considered found or not, depends on the
// systemctl parameters used.
func (e ExprEnvironment) UnitFound(unitName string) (bool, error) {
	// fill initial caches
	if len(e._state.unitsSearched) == 0 {
		if !e._state.detectOptions.SkipSystemd {
			log.Debugf("Running systemctl...")

			units, err := systemdUnitList()
			if err != nil {
				return false, err
			}

			for _, name := range units {
				e._state.installedUnits[name] = true
			}
		}

		for _, name := range e._state.detectOptions.ForcedUnits {
			e._state.installedUnits[name] = true
		}
	}

	e._state.unitsSearched[unitName] = true
	if e._state.installedUnits[unitName] {
		e._serviceState.detectedUnits = append(e._serviceState.detectedUnits, unitName)

		return true, nil
	}

	return false, nil
}

// ProcessRunning returns true if there is a running process with the given name.
func (e ExprEnvironment) ProcessRunning(processName string) (bool, error) {
	if len(e._state.processesSearched) == 0 {
		procs, err := process.Processes()
		if err != nil {
			return false, fmt.Errorf("while looking up running processes: %w", err)
		}

		for _, p := range procs {
			name, err := p.Name()
			if err != nil {
				return false, fmt.Errorf("while looking up running processes: %w", err)
			}

			e._state.runningProcesses[name] = true
		}

		for _, name := range e._state.detectOptions.ForcedProcesses {
			e._state.runningProcesses[name] = true
		}
	}

	e._state.processesSearched[processName] = true

	return e._state.runningProcesses[processName], nil
}

// return units that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedUnits() []string {
	ret := []string{}

	for _, unit := range e._state.detectOptions.ForcedUnits {
		if !e._state.unitsSearched[unit] {
			ret = append(ret, unit)
		}
	}

	return ret
}

// return processes that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedProcesses() []string {
	ret := []string{}

	for _, proc := range e._state.detectOptions.ForcedProcesses {
		if !e._state.processesSearched[proc] {
			ret = append(ret, proc)
		}
	}

	return ret
}

// checkConsumedForcedItems checks if all the "forced" options (units or processes) have been evaluated during the service detection.
func checkConsumedForcedItems(e ExprEnvironment) error {
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
