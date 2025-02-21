package cliconfig

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliConfig) newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "restore",
		Short: "This command has been removed. You can backup/restore the configuration by other means.",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			configDir := cli.cfg().ConfigPaths.ConfigDir
			return fmt.Errorf("'cscli config restore' has been removed, you can manually backup/restore %s instead", configDir)
		},
		Hidden: true,
	}

	return cmd
}
