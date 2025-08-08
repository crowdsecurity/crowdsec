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

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	//nolint:dupword
	fmt.Fprint(os.Stdout, `UNIT FILE                                 STATE    VENDOR PRESET
crowdsec-setup-detect.service            enabled  enabled
apache2.service                           enabled  enabled
apparmor.service                          enabled  enabled

3 unit files listed.`)
	os.Exit(0) //nolint:revive
}

func TestDetectSystemdUnits(t *testing.T) {
	ctx := t.Context()

	units, err := DetectSystemdUnits(ctx, fakeExecCommand)
	require.NoError(t, err)

	require.Equal(t, UnitMap{
		"crowdsec-setup-detect.service": UnitInfo{},
		"apache2.service":               UnitInfo{},
		"apparmor.service":              UnitInfo{},
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
	cstest.RequireErrorContains(t, err, `running systemctl: exec: "this-command-does-not-exist": executable file not found`)
}
