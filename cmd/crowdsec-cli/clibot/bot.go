package clibot

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type cliBot struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliBot {
	return &cliBot{cfg: cfg}
}

func (cli *cliBot) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "bot <action>",
		Short:             "Inspect bot detection: known-bot matching and fingerprint ids",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
	}

	cmd.AddCommand(cli.newMatchCmd())
	cmd.AddCommand(cli.newFsidCmd())

	return cmd
}
