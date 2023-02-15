package setup

import (
	"bufio"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// systemdUnitList returns all enabled systemd units.
// It needs to parse the table because -o json does not work everywhere.
func systemdUnitList() ([]string, error) {
	wrap := func(err error) error {
		return fmt.Errorf("running systemctl: %w", err)
	}

	ret := make([]string, 0)
	cmd := ExecCommand("systemctl", "list-unit-files", "--state=enabled,generated,static")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return ret, wrap(err)
	}

	log.Debugf("Running systemctl...")

	if err := cmd.Start(); err != nil {
		return ret, wrap(err)
	}

	scanner := bufio.NewScanner(stdout)
	header := true // skip the first line

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			break // the rest of the output is footer
		}

		if !header {
			spaceIdx := strings.IndexRune(line, ' ')
			if spaceIdx == -1 {
				return ret, fmt.Errorf("can't parse systemctl output")
			}

			line = line[:spaceIdx]
			ret = append(ret, line)
		}

		header = false
	}

	if err := cmd.Wait(); err != nil {
		return ret, wrap(err)
	}

	return ret, nil
}
