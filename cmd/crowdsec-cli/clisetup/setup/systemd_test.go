package setup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/go-cs-lib/cstest"
)

func fakeExecCommand(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	// Find the command after the "--"
	args := os.Args

	i := 0
	for ; i < len(args); i++ {
		if args[i] == "--" {
			i++
			break
		}
	}

	if i >= len(args) {
		os.Exit(2)
	}

	if args[i] == "systemctl" && i+1 < len(args) {
		sub := args[i+1]
		switch sub {
		case "show":
			// systemctl show <unit> --all --no-pager
			unit := ""
			if i+2 < len(args) {
				unit = args[i+2]
			}
			// Any valid Key=Value pairs are fine for parseUnitConfig.
			fmt.Fprint(os.Stdout, "Names="+unit+"\n")
			fmt.Fprint(os.Stdout, "StandardOutput=journal\n")
			fmt.Fprint(os.Stdout, "StandardError=journal\n")
			os.Exit(0)
		case "list-unit-files":
			// systemctl list-unit-files --type=service
			//nolint:dupword
			fmt.Fprint(os.Stdout, `UNIT FILE                                 STATE    VENDOR PRESET
crowdsec-setup-detect.service            enabled  enabled
apache2.service                           enabled  enabled
apparmor.service                          enabled  enabled

3 unit files listed.`)
			os.Exit(0)
		}
	}
}

func TestDetectSystemdUnits(t *testing.T) {
	ctx := t.Context()

	units, err := DetectSystemdUnits(ctx, fakeExecCommand)
	require.NoError(t, err)

	require.Equal(t, UnitMap{
		"crowdsec-setup-detect.service": UnitInfo{Config: UnitConfig{
			"Names":          "crowdsec-setup-detect.service",
			"StandardError":  "journal",
			"StandardOutput": "journal",
		}},
		"apache2.service": UnitInfo{Config: UnitConfig{
			"Names":          "apache2.service",
			"StandardError":  "journal",
			"StandardOutput": "journal",
		}},
		"apparmor.service": UnitInfo{Config: UnitConfig{
			"Names":          "apparmor.service",
			"StandardError":  "journal",
			"StandardOutput": "journal",
		}},
	}, units)
}

func fakeExecCommandNotFound(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, "this-command-does-not-exist", cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func TestDetectSystemdUnits_NotFound(t *testing.T) {
	ctx := t.Context()
	_, err := DetectSystemdUnits(ctx, fakeExecCommandNotFound)
	cstest.RequireErrorContains(t, err, `"systemctl list-unit-files --type=service": exec: "this-command-does-not-exist": executable file not found`)
}
