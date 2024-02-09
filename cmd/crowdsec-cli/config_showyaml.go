package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func (cli *cliConfig) showYAML() error {
	fmt.Println(mergedConfig)
	return nil
}

func (cli *cliConfig) newShowYAMLCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "show-yaml",
		Short:             "Displays merged config.yaml + config.yaml.local",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              func(_ *cobra.Command, _ []string) error {
			return cli.showYAML()
		},
	}

	return cmd
}
