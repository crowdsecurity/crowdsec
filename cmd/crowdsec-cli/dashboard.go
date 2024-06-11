//go:build linux

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

type cliDashboard struct {
	cfg configGetter
}

func NewCLIDashboard(cfg configGetter) *cliDashboard {
	return &cliDashboard{
		cfg: cfg,
	}
}

func (cli *cliDashboard) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "dashboard [command]",
		Hidden:            true,
		Short:             "Manage your metabase dashboard container [requires local API]",
		DisableAutoGenTag: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("command 'dashboard' has been removed, please read https://docs.crowdsec.net/blog/cscli_dashboard_deprecation/")
		},
	}

	return cmd
}
