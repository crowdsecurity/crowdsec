//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type cliDashboard struct{}

func NewCLIDashboard() *cliDashboard {
	return &cliDashboard{}
}

var ErrDashboardDeprecated = errors.New("command 'dashboard' has been removed, please read https://docs.crowdsec.net/blog/cscli_dashboard_deprecation/")

func (*cliDashboard) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "dashboard [command]",
		Hidden:            true,
		Short:             "Manage your metabase dashboard container [requires local API]",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return ErrDashboardDeprecated
		},
	}

	cmd.SetHelpFunc(func(_ *cobra.Command, _ []string) {
		fmt.Fprintln(os.Stdout, ErrDashboardDeprecated.Error())
	})

	return cmd
}
