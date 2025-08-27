package setup

import (
	"context"

	"github.com/shirou/gopsutil/v4/host"
)

type ExprPath interface {
	Exists(ctx context.Context, path string) bool
	Glob(ctx context.Context, glob string) []string
}

// ExprEnvironment is used to expose functions and values to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	Host    host.InfoStat
	Path    ExprPath
	Systemd *ExprSystemd
	System  *ExprSystem
	Version ExprVersion
	Windows *ExprWindows

	Ctx context.Context //nolint:containedctx
}
