package setup

import (
	"context"
	"fmt"
	"os/exec"
	"os"
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

func TestSystemdUnitLister_ListUnits(t *testing.T) {
	ctx := t.Context()
	ExecCommand = fakeExecCommand
	defer func() { ExecCommand = exec.CommandContext }()

	lister := SystemdUnitLister{}

	units, err := lister.ListUnits(ctx)
	require.NoError(t, err)

	require.Equal(t, []string{
		"crowdsec-setup-detect.service",
		"apache2.service",
		"apparmor.service",
	}, units)
}

func fakeExecCommandNotFound(ctx context.Context, command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.CommandContext(ctx, "this-command-does-not-exist", cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func TestSystemdUnitLister_ListUnits_NotFound(t *testing.T) {
	ctx := t.Context()
	ExecCommand = fakeExecCommandNotFound
	defer func() { ExecCommand = exec.CommandContext }()

	lister := SystemdUnitLister{}

	_, err := lister.ListUnits(ctx)
	cstest.RequireErrorContains(t, err, `running systemctl: exec: "this-command-does-not-exist": executable file not found in $PATH`)
}
