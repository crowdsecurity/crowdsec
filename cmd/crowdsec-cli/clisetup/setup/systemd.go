package setup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// UnitConfig holds all systemd properties for a unit.
type UnitConfig map[string]string

func NewUnitConfig(ctx context.Context, executor Executor, unit string) (UnitConfig, error) {
	cmdline := []string{"systemctl", "show", unit, "--all", "--no-pager"}
	cmd := executor(ctx, cmdline[0], cmdline[1:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	cfg, err := parseUnitConfig(stdout)
	if err != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	return cfg, nil
}

type UnitInfo struct {
	Config UnitConfig
}

// UnitMap contains all and only the installed units, whether they are enabled or not.
type UnitMap map[string]UnitInfo

type Executor func(ctx context.Context, name string, args ...string) *exec.Cmd

// parseUnitList parses the table from "systemctl list-unit-files --type=service"
func parseUnitList(r io.Reader) (UnitMap, error) {
	units := UnitMap{}
	sc := bufio.NewScanner(r)
	header := true

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // the rest is footer
		}

		if header {
			header = false
			continue
		}

		spaceIdx := strings.IndexRune(line, ' ')
		if spaceIdx == -1 {
			return units, fmt.Errorf("can't parse systemctl output: %q", line)
		}

		name := line[:spaceIdx]
		if name == "" {
			continue
		}

		if strings.Contains(name, "@.") { // skip template units
			continue
		}

		units[name] = UnitInfo{}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return units, nil
}

// parseUnitConfig reads "systemctl show <unit> --all --no-pager"
// and returns all Key=Value pairs as a UnitConfig.
func parseUnitConfig(r io.Reader) (UnitConfig, error) {
	cfg := make(UnitConfig)

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("unexpected line: %q", line)
		}

		cfg[kv[0]] = kv[1]
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func fetchUnitList(ctx context.Context, executor Executor) (UnitMap, error) {
	cmdline := []string{"systemctl", "list-unit-files", "--type=service"}
	cmd := executor(ctx, cmdline[0], cmdline[1:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	units, err := parseUnitList(stdout)
	if err != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("%q: %w", strings.Join(cmdline, " "), err)
	}

	return units, nil
}

func DetectSystemdUnits(ctx context.Context, executor Executor) (UnitMap, error) {
	units, err := fetchUnitList(ctx, executor)
	if err != nil {
		return nil, err
	}

	for name := range units {
		cfg, err := NewUnitConfig(ctx, executor, name)
		if err != nil {
			return nil, err
		}

		info := units[name]
		info.Config = cfg
		units[name] = info
	}

	return units, nil
}
