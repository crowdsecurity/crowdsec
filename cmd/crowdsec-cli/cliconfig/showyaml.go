package cliconfig

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/args"
)

func (cli *cliConfig) showYAML(mergedConfig string) error {
	fmt.Println(mergedConfig)
	return nil
}

func (cli *cliConfig) newShowYAMLCmd(mergedConfigGetter mergedConfigGetter) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "show-yaml",
		Short:             "Displays merged config.yaml + config.yaml.local",
		Args:              args.NoArgs,
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return cli.showYAML(mergedConfigGetter())
		},
	}

	return cmd
}
