package cliconfig

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/args"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type mergedConfigGetter func() string

type cliConfig struct {
	cfg csconfig.Getter
}

func New(cfg csconfig.Getter) *cliConfig {
	return &cliConfig{
		cfg: cfg,
	}
}

func (cli *cliConfig) NewCommand(mergedConfigGetter mergedConfigGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config [command]",
		Short:             "Allows to view current config",
		DisableAutoGenTag: true,
		Args:              args.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Usage()
		},
	}

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(cli.newShowYAMLCmd(mergedConfigGetter))
	cmd.AddCommand(cli.newBackupCmd())
	cmd.AddCommand(cli.newRestoreCmd())
	cmd.AddCommand(cli.newFeatureFlagsCmd())

	return cmd
}
