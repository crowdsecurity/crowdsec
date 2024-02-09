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
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(NewConfigShowYAMLCmd())
	cmd.AddCommand(NewConfigBackupCmd())
	cmd.AddCommand(NewConfigRestoreCmd())
	cmd.AddCommand(NewConfigFeatureFlagsCmd())

	return cmd
}
