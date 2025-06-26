package clisetup

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
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
	cmd := &cobra.Command{
		Use:               "setup",
		Short:             "Tools to configure crowdsec",
		Long:              "Manage service detection and hub/acquisition configuration",
		DisableAutoGenTag: true,
		Args:		   args.NoArgs,
		// XXX: TODO: examples!
		RunE: func(cmd *cobra.Command, args []string) error {
			subCmd, _, err := cmd.Root().Find([]string{"setup", "interactive"})
			if err != nil {
				return err
			}
			subCmd.SetArgs(os.Args[2:])
			return subCmd.RunE(cmd, args)
		},
	}

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newInstallAcquisitionCmd())
	cmd.AddCommand(cli.newValidateCmd())
	cmd.AddCommand(cli.newInteractiveCmd())
	cmd.AddCommand(cli.newUnattendedCmd())

	return cmd
}
