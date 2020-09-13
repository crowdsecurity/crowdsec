package main

import (
	"github.com/spf13/cobra"
)

func NewRunCommand() *cobra.Command {
	var cmdRun = &cobra.Command{
		Use:   "run",
		Short: "Run a local crowdsec API",
		Run: func(cmd *cobra.Command, args []string) {
			csAPI.Run()
		},
	}
	return cmdRun
}
