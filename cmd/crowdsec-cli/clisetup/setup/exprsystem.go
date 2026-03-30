package setup

import (
	"context"
)

type ExprSystem struct {
	runningProcesses ProcessMap
}

func NewExprSystem(runningProcesses ProcessMap) *ExprSystem {
	ret := &ExprSystem{
		runningProcesses: runningProcesses,
	}

	return ret
}

// ProcessRunning returns true if there is a running process with the given name.
func (e *ExprSystem) ProcessRunning(_ context.Context, processName string) (bool, error) {
	_, ok := e.runningProcesses[processName]

	return ok, nil
}
