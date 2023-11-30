package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewDashboardCmd() *cobra.Command {
	var cmdDashboard = &cobra.Command{
		Use:               "dashboard",
		DisableAutoGenTag: true,
		Run: func(cmd *cobra.Command, args []string) error {
			log.Infof("Dashboard command is disabled on windows")
		},
	}

	return cmdDashboard
}
