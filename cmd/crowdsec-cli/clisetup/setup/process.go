package setup

import (
	"context"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/sirupsen/logrus"
)

type ProcessMap map[string]struct{}

func DetectProcesses(ctx context.Context, additionalProcesses []string, logger logrus.FieldLogger) (ProcessMap, error) {
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}

	ret := ProcessMap{}

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			logrus.WithError(err).Warnf("Failed to get process name for PID %d", p.Pid)
			continue
		}

		ret[name] = struct{}{}
	}

	for _, name := range additionalProcesses {
		ret[name] = struct{}{}
	}

	return ret, nil
}
