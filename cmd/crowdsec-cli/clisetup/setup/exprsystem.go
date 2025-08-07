package setup

import (
	"context"
)

type ExprSystem struct {
	runningProcesses  ProcessMap
	processesSearched ProcessMap
}

func NewExprSystem(runningProcesses ProcessMap) *ExprSystem {
	ret := &ExprSystem{
		runningProcesses:  runningProcesses,
		processesSearched: make(ProcessMap),
	}

	return ret
}

// ProcessRunning returns true if there is a running process with the given name.
func (e *ExprSystem) ProcessRunning(ctx context.Context, processName string) (bool, error) {
	e.processesSearched[processName] = struct{}{}
	_, ok := e.runningProcesses[processName]

	return ok, nil
}
