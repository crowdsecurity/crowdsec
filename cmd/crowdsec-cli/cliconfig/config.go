package cliconfig

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

type configGetter func() *csconfig.Config

type mergedConfigGetter func() string

type cliConfig struct {
	cfg configGetter
}

func New(cfg configGetter) *cliConfig {
	return &cliConfig{
		cfg: cfg,
	}
}

func (cli *cliConfig) NewCommand(mergedConfigGetter mergedConfigGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "config [command]",
		Short:             "Allows to view current config",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(cli.newShowCmd())
	cmd.AddCommand(cli.newShowYAMLCmd(mergedConfigGetter))
	cmd.AddCommand(cli.newBackupCmd())
	cmd.AddCommand(cli.newRestoreCmd())
	cmd.AddCommand(cli.newFeatureFlagsCmd())

	return cmd
}
