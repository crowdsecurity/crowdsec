package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/crowdsecurity/crowdsec/pkg/cwversion"
)

type cliVersion struct{}

func NewCLIVersion() *cliVersion {
	return &cliVersion{}
}

func (cliVersion) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "version",
		Short:             "Display version",
		Args:              cobra.NoArgs,
		DisableAutoGenTag: true,
		Run: func(_ *cobra.Command, _ []string) {
			_, _ = os.Stdout.WriteString(cwversion.FullString())
		},
	}

	return cmd
}
