package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type UnitMap map[string]struct{}

type Executor func(ctx context.Context, name string, args ...string) *exec.Cmd

// DetectSystemdUnits returns all enabled systemd units.
// It needs to parse the table because -o json does not work everywhere.
// The additionalUnits parameter will force the function to return these as well, even if they are not detected.
func DetectSystemdUnits(ctx context.Context, executor Executor) (UnitMap, error) {
	ret := UnitMap{}
	cmd := executor(ctx, "systemctl", "list-unit-files", "--type=service")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("running systemctl: %w", err)
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
			ret[line] = struct{}{}
		}

		header = false
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("running systemctl: %w", err)
	}

	return ret, nil
}
