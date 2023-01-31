package main

import (
	"github.com/spf13/cobra"
)


func NewConfigCmd() *cobra.Command {
	cmdConfig := &cobra.Command{
		Use:               "config [command]",
		Short:             "Allows to view current config",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
	}

	cmdConfig.AddCommand(NewConfigShowCmd())
	cmdConfig.AddCommand(NewConfigBackupCmd())
	cmdConfig.AddCommand(NewConfigRestoreCmd())
	cmdConfig.AddCommand(NewConfigFeatureFlagsCmd())

	return cmdConfig
}
