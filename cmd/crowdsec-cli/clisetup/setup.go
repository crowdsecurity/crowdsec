package clisetup

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type configGetter func() *csconfig.Config

type cliSetup struct {
	cfg configGetter
}

func New(cfg configGetter) *cliSetup {
	return &cliSetup{
		cfg: cfg,
	}
}

func (cli *cliSetup) NewCommand() *cobra.Command {
	cmd := cli.newInteractiveCmd()
	cmd.Use = "setup"
	cmd.Short = "Tools to configure crowdsec"
	cmd.Long = "Manage service detection and hub/acquisition configuration"
	cmd.Example = `# Call one of detect, install-hub, etc.
cscli setup [command]
# With no explicit command, will run as "cscli setup interactive"
# and pass through any flags.
`
	cmd.Args = args.NoArgs

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newInstallAcquisitionCmd())
	cmd.AddCommand(cli.newValidateCmd())
	cmd.AddCommand(cli.newInteractiveCmd())
	cmd.AddCommand(cli.newUnattendedCmd())

	return cmd
}
