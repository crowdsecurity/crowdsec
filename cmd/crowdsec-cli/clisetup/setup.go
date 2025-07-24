package clisetup

import (
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/spf13/cobra"
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
	cmdInteractive := cli.newInteractiveCmd()

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Tools to configure crowdsec",
		Long:  "Manage service detection and hub/acquisition configuration",
		Example: `# Call one of detect, install-hub, etc.
cscli setup [command]
# With no explicit command, will run as "cscli setup interactive".
# It will not pass through any flag.
cscli setup
`,
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE:              cmdInteractive.RunE,
	}

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newInstallAcquisitionCmd())
	cmd.AddCommand(cli.newValidateCmd())
	cmd.AddCommand(cmdInteractive)
	cmd.AddCommand(cli.newUnattendedCmd())

	return cmd
}
