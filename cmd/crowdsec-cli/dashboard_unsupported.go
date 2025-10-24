//go:build !linux

package main

import (
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type cliDashboard struct{
}

func NewCLIDashboard(_ configGetter) *cliDashboard {
	return &cliDashboard{}
}

func (cliDashboard) NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "dashboard",
		DisableAutoGenTag: true,
		Run: func(_ *cobra.Command, _ []string) {
			log.Infof("Dashboard command is disabled on %s", runtime.GOOS)
		},
	}

	return cmd
}
