package clilapi

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type cliLapi struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliLapi {
	return &cliLapi{
		cfg: cfg,
	}
}

func (cli *cliLapi) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "lapi [action]",
		Short:             "Manage interaction with Local API (LAPI)",
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
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
