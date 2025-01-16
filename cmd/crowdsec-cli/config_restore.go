package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliConfig) newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "restore",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configDir := cli.cfg().ConfigPaths.ConfigDir
			return fmt.Errorf("'cscli config restore' has been removed, you can manually backup/restore %s instead", configDir)
		},
	}

	return cmd
}
