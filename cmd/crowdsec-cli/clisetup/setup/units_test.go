package setup_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/clisetup/setup"
)

func TestSystemdUnitList(t *testing.T) {
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	units, err := setup.SystemdUnitList() //nolint:typecheck,nolintlint  // exported only for tests
	require.NoError(t, err)

	require.Equal(t, []string{
		"crowdsec-setup-detect.service",
		"apache2.service",
		"apparmor.service",
		"apport.service",
		"atop.service",
		"atopacct.service",
		"finalrd.service",
		"fwupd-refresh.service",
		"fwupd.service",
	}, units)
}
