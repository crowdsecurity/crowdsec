package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewRunCommand() *cobra.Command {
	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "Run a local crowdsec API",
		Run: func(cmd *cobra.Command, args []string) {
			if err := csAPI.Run(); err != nil {
				log.Fatalf(err.Error())
			}
		},
	}
	return cmdRun
}
