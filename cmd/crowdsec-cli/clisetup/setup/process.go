package setup

import (
	"context"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/sirupsen/logrus"
)

type ProcessMap map[string]struct{}

func DetectProcesses(ctx context.Context, logger logrus.FieldLogger) (ProcessMap, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	ret := ProcessMap{}

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			logger.WithError(err).Warnf("Failed to get process name for PID %d", p.Pid)
			continue
		}

		ret[name] = struct{}{}
	}

	return ret, nil
}
