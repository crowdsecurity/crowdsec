package main

import (
	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

type cliVersion struct{}

func NewCLIVersion() *cliVersion {
	return &cliVersion{}
}

func (cli cliVersion) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "version",
		Short:             "Display version",
		Args:              cobra.ExactArgs(0),
		DisableAutoGenTag: true,
		Run: func(_ *cobra.Command, _ []string) {
			cwversion.Show()
		},
	}

	return cmd
}
