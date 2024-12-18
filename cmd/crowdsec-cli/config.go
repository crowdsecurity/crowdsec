package main

import (
	"github.com/spf13/cobra"
)

type cliConfig struct {
	cfg configGetter
}

func NewCLIConfig(cfg configGetter) *cliConfig {
	return &cliConfig{
		cfg: cfg,
	}
}

func (cli *cliConfig) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config [command]",
		Short:             "Allows to view current config",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(cli.newShowYAMLCmd())
	cmd.AddCommand(cli.newBackupCmd())
	cmd.AddCommand(cli.newRestoreCmd())
	cmd.AddCommand(cli.newFeatureFlagsCmd())

	return cmd
}
