package clilapi

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type configGetter = func() *csconfig.Config

type cliLapi struct {
	cfg configGetter
}

func New(cfg configGetter) *cliLapi {
	return &cliLapi{
		cfg: cfg,
	}
}

func (cli *cliLapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "lapi [action]",
		Short:             "Manage interaction with Local API (LAPI)",
		Args:              cobra.MinimumNArgs(1),
		DisableAutoGenTag: true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if err := cli.cfg().LoadAPIClient(); err != nil {
				return fmt.Errorf("loading api client: %w", err)
			}
			return nil
		},
	}

	cmd.AddCommand(cli.newRegisterCmd())
	cmd.AddCommand(cli.newStatusCmd())
	cmd.AddCommand(cli.newContextCmd())

	return cmd
}
