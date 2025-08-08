package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type UnitInfo struct {
//	HasJournal     bool
	StandardOutput string
}

// UnitMap contains all and only the installed units, whether they are enabled or not.
type UnitMap map[string]UnitInfo

type Executor func(ctx context.Context, name string, args ...string) *exec.Cmd

// collectInstalledUnits returns a UnitMap with all installed units.
// It needs to parse the table because -o json does not work everywhere.
func collectInstalledUnits(ctx context.Context, executor Executor) (UnitMap, error) {
	ret := UnitMap{}
	cmd := executor(ctx, "systemctl", "list-unit-files", "--type=service")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("starting systemctl: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("running systemctl: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	header := true // skip the first line

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // the rest of the output is footer
		}

		if !header {
			spaceIdx := strings.IndexRune(line, ' ')
			if spaceIdx == -1 {
				return ret, errors.New("can't parse systemctl output")
			}

			line = line[:spaceIdx]
			ret[line] = UnitInfo{}
		}

		header = false
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing systemctl output: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("waiting for systemctl: %w", err)
	}

	return ret, nil
}

//// markUnitsHasJournal sets HasJournal=true for every unit that has logged something through journald.
//func markUnitsHasJournal(ctx context.Context, executor Executor, units UnitMap) error {
//	cmd := executor(ctx, "journalctl", "-F", "_SYSTEMD_UNIT", "--no-pager", "--quiet")
//
//	stdout, err := cmd.StdoutPipe()
//	if err != nil {
//		return fmt.Errorf("starting journalctl: %w", err)
//	}
//
//	if err := cmd.Start(); err != nil {
//		return fmt.Errorf("running journalctl: %w", err)
//	}
//
//
//	scanner := bufio.NewScanner(stdout)
//	for scanner.Scan() {
//		unit := strings.TrimSpace(scanner.Text())
//		if unit == "" {
//			continue
//		}
//		if info, ok := units[unit]; ok {
//			info.HasJournal = true
//			units[unit] = info
//		}
//	}
//
//	if err := scanner.Err(); err != nil {
//		return fmt.Errorf("parsing journalctl output: %w", err)
//	}
//
//	if err := cmd.Wait(); err != nil {
//		return fmt.Errorf("waiting for journalctl: %w", err)
//	}
//
//	return nil
//}

// markUnitsStandardOutput fills UnitInfo.StandardOutput by querying the systemd configuration.
func markUnitsStandardOutput(ctx context.Context, executor Executor, units UnitMap) error {
	if len(units) == 0 {
		return nil
	}

	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}

	// call systemctl only once
	args := append([]string{"show"}, names...)
	args = append(args, "--property=StandardOutput", "--no-pager")

	cmd := executor(ctx, "systemctl", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running systemctl show: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	i := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Expect "StandardOutput=value"
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("unexpected systemctl show output: %q", line)
		}
		unitName := names[i]
		i++

		info := units[unitName]
		info.StandardOutput = parts[1]
		units[unitName] = info
	}

	if i != len(names) {
		return fmt.Errorf("mismatched unit count: got %d, expected %d", i, len(names))
	}

	return nil
}

// DetectSystemdUnits detects all installed units and whether they log to journald, but only if they already logged anything.
func DetectSystemdUnits(ctx context.Context, executor Executor) (UnitMap, error) {
	units, err := collectInstalledUnits(ctx, executor)
	if err != nil {
		return nil, err
	}
	if err := markUnitsStandardOutput(ctx, executor, units); err != nil {
		return nil, err
	}
	return units, nil
}
