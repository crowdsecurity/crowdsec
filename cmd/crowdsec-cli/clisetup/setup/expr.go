package setup

import (
	"context"

	"github.com/sirupsen/logrus"
)

type ExprPath interface {
	Exists(ctx context.Context, path string) bool
	Glob(ctx context.Context, glob string) []string
}

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS      ExprOS
	Path    ExprPath
	Systemd *ExprSystemd
	System  *ExprSystem

	Ctx    context.Context //nolint:containedctx
}

func (e *ExprEnvironment) checkConsumedForcedItems(logger logrus.FieldLogger) {
	e.System.checkConsumedProcesses(logger)
	e.Systemd.checkConsumedForcedUnits(logger)
}
