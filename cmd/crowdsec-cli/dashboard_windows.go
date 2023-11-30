//go:build !linux

package main

import (
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewDashboardCmd() *cobra.Command {
	var cmdDashboard = &cobra.Command{
		Use:               "dashboard",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) {
			log.Infof("Dashboard command is disabled on %s", runtime.GOOS)
		},
	}

	return cmdDashboard
}
