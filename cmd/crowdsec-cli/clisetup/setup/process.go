package setup

import (
	"context"

	"github.com/shirou/gopsutil/v3/process"
)

type ProcessMap map[string]struct{}

func DetectProcesses(ctx context.Context, additionalProcesses []string) (ProcessMap, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	ret := ProcessMap{}

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			return nil, err
		}

		ret[name] = struct{}{}
	}

	for _, name := range additionalProcesses {
		ret[name] = struct{}{}
	}

	return ret, nil
}
