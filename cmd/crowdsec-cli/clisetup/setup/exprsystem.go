package setup

import (
	"context"

	"github.com/sirupsen/logrus"
)

type ExprSystem struct {
	forcedProcesses   ProcessMap
	runningProcesses  ProcessMap
	processesSearched ProcessMap
}

func NewExprSystem(runningProcesses ProcessMap, forcedProcesses []string) *ExprSystem {
	ret := &ExprSystem{
		runningProcesses:  runningProcesses,
		processesSearched: make(ProcessMap),
	}

	ret.forcedProcesses = make(ProcessMap)

	for _, proc := range forcedProcesses {
		ret.forcedProcesses[proc] = struct{}{}
	}

	return ret
}

// ProcessRunning returns true if there is a running process with the given name.
func (e *ExprSystem) ProcessRunning(ctx context.Context, processName string) (bool, error) {
	e.processesSearched[processName] = struct{}{}
	_, ok := e.runningProcesses[processName]

	return ok, nil
}

// unsearchedProcesses() returns processes that have been forced but not searched yet.
func (e *ExprSystem) unsearchedProcesses() []string {
	ret := []string{}

	for proc := range e.forcedProcesses {
		if _, ok := e.processesSearched[proc]; !ok {
			ret = append(ret, proc)
		}
	}

	return ret
}

// checkConsumedProcesses checks if all the "forced" processes have been evaluated during the service detection.
func (e *ExprSystem) checkConsumedProcesses(logger logrus.FieldLogger) {
	unconsumed := e.unsearchedProcesses()

	if len(unconsumed) > 0 {
		logger.Warnf("No service matched the following processes: %v. They are likely unsupported by the detection configuration.", unconsumed)
	}
}
