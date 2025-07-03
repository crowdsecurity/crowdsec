package setup

import (
	"context"
	"maps"
	"slices"

	"github.com/shirou/gopsutil/v3/process"
)

type GopsutilProcessLister struct{}

func (GopsutilProcessLister) ListProcesses(ctx context.Context) ([]string, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	ret := make(map[string]struct{}, 0)

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			return nil, err
		}

		ret[name] = struct{}{}
	}

	return slices.Collect(maps.Keys(ret)), nil
}
