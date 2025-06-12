package clisetup

import (
	"github.com/spf13/cobra"

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
	cmd := &cobra.Command{
		Use:               "setup",
		Short:             "Tools to configure crowdsec",
		Long:              "Manage hub configuration and service detection",
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newDetectCmd())
	cmd.AddCommand(cli.newInstallHubCmd())
	cmd.AddCommand(cli.newDataSourcesCmd())
	cmd.AddCommand(cli.newValidateCmd())

	return cmd
}
