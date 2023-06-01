package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func runConfigShowYAML(cmd *cobra.Command, args []string) error {
	fmt.Println(mergedConfig)
	return nil
}

func NewConfigShowYAMLCmd() *cobra.Command {
	cmdConfigShow := &cobra.Command{
		Use:               "show-yaml",
		Short:             "Displays merged config.yaml + config.yaml.local",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		RunE:              runConfigShowYAML,
	}

	return cmdConfigShow
}
