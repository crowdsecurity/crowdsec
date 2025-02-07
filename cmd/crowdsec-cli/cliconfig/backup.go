package cliconfig

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliConfig) newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "backup",
		Short: "This command has been removed. You can backup/restore the configuration by other means.",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			configDir := cli.cfg().ConfigPaths.ConfigDir
			return fmt.Errorf("'cscli config backup' has been removed, you can manually backup/restore %s instead", configDir)
		},
		Hidden: true,
	}

	return cmd
}
